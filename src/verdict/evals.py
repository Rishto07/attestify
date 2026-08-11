"""Eval corpus and harness — measure Verdict's precision and recall.

The corpus lives in ``evals/data/*.json`` (data, not code, so anyone can
contribute a case). The harness runs the real checkers against it and reports
honest numbers: accuracy, precision, recall, F1, and the confusion matrix.

This module has three metric modes, one per dataset:
- ``quarantine``    → precision/recall on "dangerous pattern found" (FAIL)
- ``execute_proof`` → accuracy on code-execution outcomes (PASS/FAIL/UNKNOWN)
- ``prosecutor``    → judge agreement on known-true/false factual claims

Design rule: evaluation is the backbone of trust. Every change to Verdict is
measured against this corpus, and we publish the numbers. That's how we earn
trust — not by saying "trust us," but by showing our work.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .core import CheckContext, Evidence, Verdict, VerdictValue
from .execute_proof import ExecuteProofChecker
from .llm import get_llm
from .prosecutor import ProsecutorChecker
from .quarantine import QuarantineChecker
from .sandbox import SubprocessSandbox

# Where the corpus lives. Resolved relative to this file so the package
# works installed *and* from a source checkout.
_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "evals" / "data"


# === CORPUS LOADING ===

class EvalError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvalCase:
    id: str
    input: str
    note: str = ""
    # For quarantine / execute_proof:
    expected: Optional[str] = None
    # For prosecutor:
    truth: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        d = {"id": self.id, "input": self.input, "note": self.note}
        if self.expected is not None:
            d["expected"] = self.expected
        if self.truth is not None:
            d["truth"] = self.truth
        return d


@dataclass(frozen=True)
class EvalDataset:
    name: str
    description: str
    metric: str  # "precision_recall" | "accuracy" | "agreement"
    positive: str  # which verdict value is the "positive" class (e.g. "FAIL")
    cases: tuple[EvalCase, ...] = field(default_factory=tuple)

    @staticmethod
    def load(path: Path) -> "EvalDataset":
        if not path.exists():
            raise EvalError(f"eval corpus not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        cases = tuple(
            EvalCase(
                id=c.get("id", f"{data['name']}-{i}"),
                input=c["input"],
                note=c.get("note", ""),
                expected=c.get("expected"),
                truth=c.get("truth"),
            )
            for i, c in enumerate(data.get("cases", []))
        )
        return EvalDataset(
            name=data["name"],
            description=data.get("description", ""),
            metric=data.get("metric", "accuracy"),
            positive=data.get("positive", "FAIL"),
            cases=cases,
        )


def load_all_datasets(data_dir: Optional[Path] = None) -> list[EvalDataset]:
    data_dir = Path(data_dir) if data_dir else _DATA_DIR
    datasets = []
    for path in sorted(data_dir.glob("*.json")):
        datasets.append(EvalDataset.load(path))
    return datasets


# === METRICS ===

@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    unknown: int = 0  # predicted UNKNOWN — counted as a hedge, not a class

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        denom = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        """How often a benign case gets wrongly flagged. Trust killer #1."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        """How often a real threat slips through. Trust killer #2."""
        denom = self.fn + self.tp
        return self.fn / denom if denom else 0.0


def _classify_case(
    actual: VerdictValue,
    expected: VerdictValue,
    positive: str,
) -> tuple[str, Confusion]:
    """Classify one case into the confusion matrix.

    For quarantine, positive = FAIL (we found danger). For execute_proof,
    positive = PASS (code ran). Predicted UNKNOWN is always a hedge.
    """
    cm = Confusion()
    if actual is VerdictValue.UNKNOWN:
        cm.unknown = 1
        return "UNKNOWN-hedge", cm

    actual_pos = actual.value == positive
    expected_pos = expected.value == positive

    if actual_pos and expected_pos:
        cm.tp = 1
        return "TP", cm
    if actual_pos and not expected_pos:
        cm.fp = 1
        return "FP", cm
    if not actual_pos and expected_pos:
        cm.fn = 1
        return "FN", cm
    cm.tn = 1
    return "TN", cm


@dataclass
class MetricResult:
    name: str
    description: str
    confusion: Confusion
    unknown_count: int
    total: int
    cases: list[tuple[EvalCase, VerdictValue, VerdictValue]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def summarize(self) -> dict[str, Any]:
        c = self.confusion
        return {
            "total": self.total,
            "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn,
            "unknown": c.unknown,
            "accuracy": round(c.accuracy, 4),
            "precision": round(c.precision, 4),
            "recall": round(c.recall, 4),
            "f1": round(c.f1, 4),
            "false_positive_rate": round(c.false_positive_rate, 4),
            "false_negative_rate": round(c.false_negative_rate, 4),
            "detail": self.detail,
        }


def _run_checkers(case_input: str, ctx: CheckContext) -> dict[str, Evidence]:
    """Run the deterministic checkers; prosecutor optional via ctx.llm."""
    evidence = {}
    checkers: list[Evidence] = []

    q = QuarantineChecker().check(case_input, ctx)
    e = ExecuteProofChecker().check(case_input, ctx)
    evidence["quarantine"] = q
    evidence["execute_proof"] = e

    if ctx.llm is not None:
        p = ProsecutorChecker(llm=ctx.llm).check(case_input, ctx)
        evidence["prosecutor"] = p

    return evidence


def _expected_for(dataset: EvalDataset, case: EvalCase) -> Optional[VerdictValue]:
    if dataset.metric == "agreement":
        # For the prosecutor, "expected" derives from ground truth:
        # false claim → FAIL (should be refuted), true claim → PASS.
        return VerdictValue.FAIL if case.truth is False else VerdictValue.PASS
    if case.expected:
        try:
            return VerdictValue(case.expected)
        except ValueError:
            return None
    return None


def run_dataset(
    dataset: EvalDataset,
    ctx: CheckContext,
    verbose: bool = False,
) -> MetricResult:
    """Run one dataset through the checkers and produce metrics."""
    total = len(dataset.cases)
    cm = Confusion()
    unknown_count = 0
    results: list[tuple[EvalCase, VerdictValue, VerdictValue]] = []

    # Each dataset is scored by its OWN checker — not a cross-checker aggregate.
    # Quarantine cases must be judged by the quarantine scanner, execute_proof
    # cases by the code runner, prosecutor cases by the judge. Aggregating
    # across checkers would let one checker's UNKNOWN drag another's scores.
    owner = {
        "quarantine": "quarantine",
        "execute_proof": "execute_proof",
        "prosecutor": "prosecutor",
    }.get(dataset.name, None)

    for case in dataset.cases:
        expected = _expected_for(dataset, case)
        if expected is None:
            continue  # skip malformed cases, count them in detail later

        evidence = _run_checkers(case.input, ctx)

        if owner is not None and owner in evidence:
            actual = evidence[owner].conclusion
        else:
            actual = Verdict.aggregate(list(evidence.values())).value

        results.append((case, expected, actual))
        tag, one_cm = _classify_case(actual, expected, dataset.positive)
        if tag == "UNKNOWN-hedge":
            unknown_count += 1
        cm.tp += one_cm.tp
        cm.fp += one_cm.fp
        cm.tn += one_cm.tn
        cm.fn += one_cm.fn
        cm.unknown += one_cm.unknown

        if verbose:
            mark = "✓" if (actual == expected) else "✗"
            print(f"  {mark} {case.id}: expected {expected.value}, got {actual.value}"
                  + (f" — {case.note}" if case.note else ""))

    return MetricResult(
        name=dataset.name,
        description=dataset.description,
        confusion=cm,
        unknown_count=unknown_count,
        total=total,
        cases=results,
    )


def run_all(data_dir: Optional[Path] = None, verbose: bool = False) -> list[MetricResult]:
    # Fast subprocess sandbox on purpose: the eval measures *checker logic*,
    # not container spin-up. The Docker isolation path has its own tests.
    # The prosecutor (agreement) dataset needs an LLM, so it runs separately.
    ctx = CheckContext(timeout=5.0, sandbox=SubprocessSandbox())
    offline = [ds for ds in load_all_datasets(data_dir) if ds.metric != "agreement"]
    return [run_dataset(ds, ctx, verbose=verbose) for ds in offline]


def run_prosecutor_eval(
    data_dir: Optional[Path] = None,
    verbose: bool = False,
) -> MetricResult:
    """Run the prosecutor dataset against the configured LLM.

    This is the number that earns trust for the adversarial judge: how often
    it correctly refutes false claims and correctly verifies true ones.
    """
    datasets = load_all_datasets(data_dir)
    try:
        ds = next(d for d in datasets if d.metric == "agreement")
    except StopIteration:
        raise EvalError("no prosecutor (agreement) dataset found in corpus")

    llm = get_llm()
    ctx = CheckContext(timeout=120.0, llm=llm, model=None, sandbox=SubprocessSandbox())
    return run_dataset(ds, ctx, verbose=verbose)


# === REPORTING ===

def print_report(results: Iterable[MetricResult], as_json: bool = False) -> None:
    results = list(results)
    if as_json:
        payload = {
            "summary": {
                "datasets": len(results),
                "results": [r.summarize() for r in results],
            }
        }
        print(json.dumps(payload, indent=2))
        return

    print("\n" + "=" * 64)
    print("VERDICT EVALUATION REPORT")
    print("=" * 64)

    for r in results:
        s = r.summarize()
        print(f"\n[{r.name}]  {r.description}")
        print("-" * 64)
        if r.detail:
            for k, v in r.detail.items():
                print(f"  {k}: {v}")
        print(f"  total            : {s['total']}   (predicted UNKNOWN: {s['unknown']})")
        print(f"  TP {s['tp']}  FP {s['fp']}  TN {s['tn']}  FN {s['fn']}")
        print(f"  accuracy         : {s['accuracy']:.2%}")
        print(f"  precision        : {s['precision']:.2%}   (flagged, how often right)")
        print(f"  recall           : {s['recall']:.2%}   (real cases, how many caught)")
        print(f"  F1               : {s['f1']:.2%}")
        print(f"  false-positive   : {s['false_positive_rate']:.2%}   (safe stuff wrongly flagged)")
        print(f"  false-negative   : {s['false_negative_rate']:.2%}   (danger that slipped through)")

    print("\n" + "=" * 64)


# === CLI ===

def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for `verdict evals`.

    Usage:
        verdict evals                # offline checkers only (quarantine + execute)
        verdict evals --prosecutor   # + judge-reliability eval (needs LLM in .env)
        verdict evals --json         # machine-readable report
    """
    import argparse

    parser = argparse.ArgumentParser(prog="verdict evals", description="Run Verdict's evaluation corpus.")
    parser.add_argument("--prosecutor", action="store_true", help="Also run the prosecutor judge-reliability eval (uses .env LLM)")
    parser.add_argument("--verbose", action="store_true", help="Show per-case results")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a human report")
    parser.add_argument("--data-dir", type=Path, default=None, help="Override the corpus directory")
    args = parser.parse_args(argv)

    try:
        results = run_all(args.data_dir, verbose=args.verbose)
        if args.prosecutor:
            results.append(run_prosecutor_eval(args.data_dir, verbose=args.verbose))
    except EvalError as e:
        print(f"eval error: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # LLM/proxy failures shouldn't nuke the whole run
        print(f"eval error: {e}", file=sys.stderr)
        return 1

    print_report(results, as_json=args.json)

    # Exit non-zero if any dataset's accuracy is embarrassingly low.
    bad = [r for r in results if r.confusion.accuracy < 0.85]
    if bad:
        print("\n[!!] One or more datasets below 85% accuracy — investigate before trusting.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())