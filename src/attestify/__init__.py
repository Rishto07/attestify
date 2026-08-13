"""Attestify — the trust layer for AI output.

Accept nothing on faith: verify with proof, prosecute with an adversary,
quarantine before it can hurt you.

Quick start:
    pip install attestify
    attestify check "your AI output here"

Or in Python:
    from attestify import run_verdict
    result = run_verdict("your AI output")
    print(result.value)  # PASS, FAIL, or UNKNOWN
"""

from .core import (
    Checker,
    CheckContext,
    Evidence,
    Receipt,
    Verdict,
    VerdictValue,
)
from .execute_proof import ExecuteProofChecker
from .llm import get_llm
from .prosecutor import ProsecutorChecker, GroundTruthChecker
from .quarantine import QuarantineChecker
from .sandbox import DockerSandbox, Sandbox, SubprocessSandbox, get_sandbox
from .storage import ReceiptStore

__version__ = "0.1.1"

__all__ = [
    "Checker",
    "CheckContext",
    "Evidence",
    "Receipt",
    "Verdict",
    "VerdictValue",
    "ExecuteProofChecker",
    "ProsecutorChecker",
    "GroundTruthChecker",
    "QuarantineChecker",
    "DockerSandbox",
    "SubprocessSandbox",
    "Sandbox",
    "get_sandbox",
    "get_llm",
    "ReceiptStore",
    "run_verdict",
]


def run_verdict(
    output: str,
    checkers: list[Checker] | None = None,
    llm=None,
    timeout: float = 10.0,
    model: str | None = None,
    sandbox=None,
) -> Verdict:
    """Run attestify on the given output.

    Args:
        output: The AI output to verify
        checkers: List of checkers to run (default: quarantine + execute_proof)
        llm: LLM client for prosecutor (optional)
        timeout: Timeout for execution checks
        model: Model name for LLM
        sandbox: Sandbox instance to run code in (default: auto-selected)

    Returns:
        Verdict object with value, confidence, summary, and evidence
    """
    from .core import CheckContext

    if checkers is None:
        checkers = [QuarantineChecker(), ExecuteProofChecker()]

    ctx = CheckContext(
        timeout=timeout,
        llm=llm,
        model=model,
        sandbox=sandbox,
    )

    evidence = []
    for checker in checkers:
        e = checker.check(output, ctx)
        evidence.append(e)

    return Verdict.aggregate(evidence)