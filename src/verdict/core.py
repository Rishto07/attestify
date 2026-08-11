"""Core data model for Verdict.

The whole project is built on four small ideas:

- ``Evidence`` — one fact produced by one checker. Checkers never *decide*,
  they *testify*.
- ``Verdict`` — the aggregate of all evidence for one output.
- ``Receipt`` — an immutable, hash-locked record of a verdict. You can trust
  the receipt even when you don't trust the model.
- ``Checker`` — the protocol every verifier implements.

Design rule #1 of this project: *no fake complexity*. Every piece of this file
pays for itself, and the entire runtime dependency footprint of Verdict is the
Python standard library. A trust tool that depends on a huge dependency graph
is a trust tool you cannot trust.
"""

from __future__ import annotations

import abc
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional


class VerdictValue(str, Enum):
    """What a checker (or a whole pipeline) concluded about an output."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:  # so CLI output reads PASS/FAIL/UNKNOWN, not VerdictValue.PASS
        return self.value


@dataclass(frozen=True)
class Evidence:
    """One testimony from one checker, about one output.

    ``data`` is free-form and may carry machine-readable payloads (e.g. which
    assertion ran, which dangerous pattern matched). ``detail`` is a short
    human-readable sentence used in the CLI and in receipts.
    """

    checker: str
    conclusion: VerdictValue
    detail: str
    data: dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker": self.checker,
            "conclusion": self.conclusion.value,
            "detail": self.detail,
            "data": self.data,
            "weight": self.weight,
        }


@dataclass(frozen=True)
class Verdict:
    """The aggregate decision about one output.

    Aggregation is deliberately simple, documented, and easy to reason about:

    - ``FAIL`` wins: any evidence with ``weight >= fail_threshold`` that
      concluded FAIL makes the whole verdict FAIL.
    - Otherwise ``PASS`` requires at least one positive signal
      (``weight >= pass_threshold``) and no open questions.
    - Otherwise ``UNKNOWN`` — we honestly do not know, and we say so.

    ``confidence`` is a number in [0, 1] from the same evidence. It is a
    *reported* number, never a guarantee.
    """

    value: VerdictValue
    confidence: float
    summary: str
    evidence: tuple[Evidence, ...]
    fail_threshold: float = 1.0
    pass_threshold: float = 1.0

    @staticmethod
    def aggregate(
        evidence: Iterable[Evidence],
        fail_threshold: float = 1.0,
        pass_threshold: float = 1.0,
    ) -> "Verdict":
        ev = tuple(evidence)
        total = sum(e.weight for e in ev) or 0.0
        weighted_pass = sum(e.weight for e in ev if e.conclusion is VerdictValue.PASS)
        weighted_fail = sum(e.weight for e in ev if e.conclusion is VerdictValue.FAIL)
        weighted_unknown = sum(e.weight for e in ev if e.conclusion is VerdictValue.UNKNOWN)

        failing = weighted_fail >= fail_threshold
        passing = weighted_pass >= pass_threshold

        if failing:
            value = VerdictValue.FAIL
            confidence = weighted_pass / total if total else 0.0
            summary = _summarize_failure(ev)
        elif passing and weighted_unknown == 0:
            value = VerdictValue.PASS
            confidence = 1.0
            summary = "Every check passed."
        else:
            value = VerdictValue.UNKNOWN
            confidence = weighted_pass / total if total else 0.0
            summary = (
                "Not enough evidence to pass or fail. "
                f"{weighted_fail:.2g} weight of failures, {weighted_pass:.2g} weight of passes, "
                f"{weighted_unknown:.2g} weight unanswered."
            )

        if not ev:
            return Verdict(VerdictValue.UNKNOWN, 0.0, "No checkers ran — nothing to say.", ())

        return Verdict(value, round(confidence, 4), summary, ev, fail_threshold, pass_threshold)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def _summarize_failure(evidence: tuple[Evidence, ...]) -> str:
    """First failing detail, then a count — the receipt keeps every one."""
    for e in evidence:
        if e.conclusion is VerdictValue.FAIL:
            return f"FAIL: {e.checker} — {e.detail}"
    return "FAIL: one or more checks failed."


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Stable hashes, stable receipts."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _preview(text: str, n: int = 200) -> str:
    text = " ".join(text.split())
    return text[:n] + ("…" if len(text) > n else "")


@dataclass(frozen=True)
class Receipt:
    """An immutable, hash-locked record of one verdict.

    ``signature`` is the SHA-256 over the canonical JSON of everything else in
    the receipt. Anyone can re-verify a receipt by recomputing it; anyone can
    replay the exact evidence a verdict rested on. That is the point: Verdict
    stores *receipts*, not opinions.
    """

    receipt_id: str
    input_hash: str
    input_preview: str
    pipeline: str
    verdict: VerdictValue
    confidence: float
    summary: str
    evidence: tuple[dict[str, Any], ...]
    model: Optional[str]
    created_at: str
    signature: str

    @staticmethod
    def create(
        output: str,
        verdict_obj: Verdict,
        pipeline: str,
        model: Optional[str] = None,
    ) -> "Receipt":
        payload: dict[str, Any] = {
            "receipt_id": uuid.uuid4().hex,
            "input_hash": sha256_hex(output),
            "input_preview": _preview(output),
            "pipeline": pipeline,
            "verdict": verdict_obj.value.value,
            "confidence": verdict_obj.confidence,
            "summary": verdict_obj.summary,
            "evidence": [e.to_dict() for e in verdict_obj.evidence],
            "model": model,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        signature = sha256_hex(_canonical_json(payload))
        payload["signature"] = signature
        return Receipt(**payload)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Receipt":
        data = dict(data)
        sig = data.pop("signature", None)
        receipt = Receipt(**data, signature=sig or "")
        return receipt

    def verify_signature(self) -> bool:
        """Recompute the signature over everything except the signature field."""
        data = dict(self.to_dict())
        data.pop("signature", None)
        return self.signature == sha256_hex(_canonical_json(data))

    def verify_input(self, output: str) -> bool:
        return self.input_hash == sha256_hex(output)


class CheckContext:
    """What a checker is allowed to depend on.

    Keep this deliberately small: ``timeout`` and an optional LLM client.
    Checkers that want more (filesystem, network) must say so — the quarantine
    exists precisely because most of that is untrusted.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        llm: Optional["VerdictLLM"] = None,
        model: Optional[str] = None,
        workdir: Optional[str] = None,
        sandbox: Optional[Any] = None,
    ) -> None:
        self.timeout = timeout
        self.llm = llm
        self.model = model
        self.workdir = workdir
        # A Sandbox instance (verdict.sandbox). Kept as Any to avoid a hard
        # import cycle from core -> sandbox; the protocol is duck-typed.
        self.sandbox = sandbox


class Checker(abc.ABC):
    """The protocol every checker must implement.

    ``name`` is the stable identity used in receipts. ``weight`` says how much
    this checker's FAIL counts against the overall verdict.
    """

    name: str = "checker"
    weight: float = 1.0

    @abc.abstractmethod
    def check(self, output: str, ctx: CheckContext) -> Evidence:  # pragma: no cover
        """Examine ``output`` and testify about it."""
        raise NotImplementedError