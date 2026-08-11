"""Prosecutor: the adversarial checker that tries to prove output wrong.

This is the second opinion — a separate LLM pass that actively tries to
refute the first output. The insight from research (debate protocols,
self-check limitations) is that a model checking its own work often repeats
the same error. The Prosecutor is a *different* model (or at least a *different
prompt*) whose only job is to find what the first pass got wrong.

The Prosecutor doesn't know what the original prompt was. It only sees the
output and is asked: "Is this correct? Prove it's wrong if you can."

Design: This is intentionally expensive (an extra LLM call), so it only runs
on content that has already raised questions. The pipeline decides when to
invoke it based on quarantine or other signals.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .core import Checker, CheckContext, Evidence, VerdictValue
from .llm import VerdictLLM, get_llm, extract_json


# The adversarial prompt: this is the secret sauce. Tweaking this prompt
# is where the research lives — everything else is plumbing.
PROSECUTOR_PROMPT = """You are a skeptical fact-checker. Your job is to examine the following AI output and try to prove it WRONG.

Your standards:
- Question every factual claim — verify against your knowledge
- Check code for bugs, security issues, or logic errors
- Look for hallucinations, made-up citations, or unverified statistics
- If you find something wrong, cite the specific error and explain why

Output your verdict in JSON format:
{{
  "verdict": "PASS"|"FAIL"|"UNKNOWN",
  "confidence": 0.0-1.0,
  "challenges": [
    {{
      "type": "factual|security|logic|citation|other",
      "claim": "the specific claim you're challenging",
      "reason": "why you believe this is wrong",
      "evidence": "what you know that contradicts this"
    }}
  ],
  "summary": "one sentence on why you passed or failed"
}}

If you cannot find concrete errors, return PASS with confidence 0.5-0.8.
If you find clear errors, return FAIL with confidence 0.7-1.0.
If you're genuinely unsure, return UNKNOWN with confidence 0.3-0.6.

---

AI OUTPUT TO EXAMINE:
---
{output}
---

Your verdict:"""


# Simplified prompt for "ground truth" checking — verifies claims against sources
GROUND_TRUTH_PROMPT = """You are a citation verifier. The following output makes claims. For each claim, determine:

1. Is it supported by the cited source?
2. If no source is cited, can you verify it from general knowledge?

Output JSON:
{{
  "verdict": "PASS"|"FAIL"|"UNKNOWN",
  "claims": [
    {{
      "text": "the exact claim",
      "supported": true|false,
      "source": "URL or source cited, or 'general knowledge'",
      "issue": "what's wrong if unsupported"
    }}
  ],
  "summary": "overall assessment"
}}

---
OUTPUT TO VERIFY:
---
{output}
---

Verdict:"""


def split_into_claims(text: str) -> list[str]:
    """Naive claim splitter — splits on sentences and bullet points."""
    # Split on newlines that look like list items
    lines = text.split("\n")
    claims = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Skip code blocks, headers, etc
        if line.startswith("```") or line.startswith("#") or line.startswith("---"):
            continue
        # This is naive — better claim extraction is a research problem
        if len(line) > 20:  # skip very short lines
            claims.append(line)
    return claims


class ProsecutorChecker(Checker):
    """The adversarial checker — a second opinion that tries to refute."""

    name = "prosecutor"
    weight = 1.2  # slightly higher weight since it's the "expert" check

    def __init__(self, llm: Optional[VerdictLLM] = None):
        self.llm = llm

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        # If no LLM configured, we can't run the prosecutor
        if ctx.llm is None:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No LLM configured — prosecutor cannot run.",
                data={"configured": False},
                weight=self.weight * 0.3,
            )

        # Run the adversarial check
        prompt = PROSECUTOR_PROMPT.format(output=output[:8000])  # limit length

        try:
            result = ctx.llm.complete(
                prompt,
                model=ctx.model,
                temperature=0.2,  # low temp for consistency
                max_tokens=2048,
            )
            response = result.text
        except Exception as e:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail=f"Prosecutor call failed: {e}",
                data={"error": str(e)},
                weight=self.weight * 0.3,
            )

        # Parse the JSON response
        parsed = extract_json(response)
        if parsed is None:
            # Fallback: try to parse from text
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="Prosecutor returned unparseable response",
                data={"raw_response": response[:500]},
                weight=self.weight * 0.5,
            )

        verdict_str = parsed.get("verdict", "UNKNOWN")
        confidence = parsed.get("confidence", 0.5)
        challenges = parsed.get("challenges", [])
        summary = parsed.get("summary", "")

        if verdict_str == "FAIL":
            conclusion = VerdictValue.FAIL
            detail = f"REFUTED: {len(challenges)} challenge(s) found. {summary}"
        elif verdict_str == "PASS":
            conclusion = VerdictValue.PASS
            detail = f"VERIFIED: prosecutor found no issues. {summary}"
        else:
            conclusion = VerdictValue.UNKNOWN
            detail = f"Uncertain: {summary}"

        return Evidence(
            checker=self.name,
            conclusion=conclusion,
            detail=detail,
            data={
                "verdict": verdict_str,
                "confidence": confidence,
                "challenges": challenges,
                "summary": summary,
                "model": result.model,
                "latency_ms": result.latency_ms,
            },
            weight=self.weight,
        )


class GroundTruthChecker(Checker):
    """Verify citations and factual claims against sources."""

    name = "ground_truth"
    weight = 1.0

    def __init__(self, llm: Optional[VerdictLLM] = None):
        self.llm = llm

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        if ctx.llm is None:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No LLM configured — ground truth check cannot run.",
                data={"configured": False},
                weight=self.weight * 0.3,
            )

        # Check for citations/URLs in the output
        has_citations = bool(re.search(r"https?://|www\.|According to|Source:", output))

        if not has_citations:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No citations found to verify.",
                data={"has_citations": False},
                weight=self.weight * 0.3,
            )

        prompt = GROUND_TRUTH_PROMPT.format(output=output[:6000])

        try:
            result = ctx.llm.complete(
                prompt,
                model=ctx.model,
                temperature=0.1,
                max_tokens=1024,
            )
            response = result.text
        except Exception as e:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail=f"Ground truth check failed: {e}",
                data={"error": str(e)},
                weight=self.weight * 0.3,
            )

        parsed = extract_json(response)
        if parsed is None:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="Could not parse ground truth response",
                data={"raw": response[:300]},
                weight=self.weight * 0.5,
            )

        claims = parsed.get("claims", [])
        supported = sum(1 for c in claims if c.get("supported", False))
        total = len(claims)

        if total == 0:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No claims found to verify.",
                data={"claims": []},
                weight=self.weight * 0.5,
            )

        if supported == total:
            conclusion = VerdictValue.PASS
            detail = f"VERIFIED: {supported}/{total} claims supported by sources."
        elif supported == 0:
            conclusion = VerdictValue.FAIL
            detail = f"REFUTED: 0/{total} claims verified — all appear unsupported."
        else:
            conclusion = VerdictValue.UNKNOWN
            detail = f"Uncertain: {supported}/{total} claims verified."

        return Evidence(
            checker=self.name,
            conclusion=conclusion,
            detail=detail,
            data={
                "claims": claims,
                "supported": supported,
                "total": total,
                "summary": parsed.get("summary", ""),
            },
            weight=self.weight,
        )