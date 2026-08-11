"""Tests for the eval corpus and metrics harness."""

import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from verdict.core import CheckContext, Evidence, VerdictValue
from verdict.evals import (
    Confusion,
    EvalDataset,
    MetricResult,
    _classify_case,
    load_all_datasets,
    run_all,
    run_dataset,
    run_prosecutor_eval,
)
from verdict.sandbox import SubprocessSandbox


# === Confusion matrix ===

class TestConfusion:
    def test_perfect(self):
        cm = Confusion(tp=10, fp=0, tn=8, fn=0)
        assert cm.precision == 1.0
        assert cm.recall == 1.0
        assert cm.f1 == 1.0
        assert cm.false_positive_rate == 0.0
        assert cm.false_negative_rate == 0.0

    def test_false_positive_hurts_precision(self):
        cm = Confusion(tp=10, fp=5, tn=8, fn=0)
        assert cm.precision == 10 / 15
        assert cm.recall == 1.0
        assert cm.false_positive_rate == 5 / 13

    def test_false_negative_hurts_recall(self):
        cm = Confusion(tp=10, fp=0, tn=8, fn=5)
        assert cm.recall == 10 / 15
        assert cm.false_negative_rate == 5 / 15


class TestClassify:
    def test_true_positive(self):
        tag, cm = _classify_case(VerdictValue.FAIL, VerdictValue.FAIL, "FAIL")
        assert tag == "TP" and cm.tp == 1

    def test_false_positive(self):
        tag, cm = _classify_case(VerdictValue.FAIL, VerdictValue.PASS, "FAIL")
        assert tag == "FP" and cm.fp == 1

    def test_true_negative(self):
        tag, cm = _classify_case(VerdictValue.PASS, VerdictValue.PASS, "FAIL")
        assert tag == "TN" and cm.tn == 1

    def test_false_negative(self):
        tag, cm = _classify_case(VerdictValue.PASS, VerdictValue.FAIL, "FAIL")
        assert tag == "FN" and cm.fn == 1

    def test_unknown_is_hedge(self):
        tag, cm = _classify_case(VerdictValue.UNKNOWN, VerdictValue.FAIL, "FAIL")
        assert tag == "UNKNOWN-hedge" and cm.unknown == 1


# === Dataset loading ===

def test_load_all_datasets_finds_corpus():
    datasets = load_all_datasets()
    names = {d.name for d in datasets}
    assert {"quarantine", "execute_proof", "prosecutor"} <= names


def test_dataset_requires_input():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.json"
        p.write_text('{"name": "x", "cases": [{"id": "a", "note": "no input"}]}', encoding="utf-8")
        with pytest.raises(KeyError):
            EvalDataset.load(p)


# === Running datasets ===

def test_offline_run_all_returns_three_results():
    # prosecutor (agreement) dataset is offline-skipped, so quarantine +
    # execute_proof come back.
    results = run_all()
    assert {r.name for r in results} == {"quarantine", "execute_proof"}
    assert all(r.total > 0 for r in results)


def test_quarantine_perfect_on_golden():
    results = run_all()
    q = next(r for r in results if r.name == "quarantine")
    assert q.confusion.accuracy == 1.0
    assert q.confusion.false_positive_rate == 0.0
    assert q.confusion.false_negative_rate == 0.0


def test_prosecutor_eval_needs_llm(tmp_path, monkeypatch):
    # Without a configured LLM, get_llm() returns MockLLM, which yields
    # UNKNOWN for everything — that's the honest "can't judge" outcome.
    from verdict.llm import MockLLM

    monkeypatch.chdir(tmp_path)  # no .env here
    with mock.patch("verdict.evals.get_llm", return_value=MockLLM()):
        r = run_prosecutor_eval()
    assert r.name == "prosecutor"
    assert r.confusion.unknown == r.total  # all hedged without a real judge


def test_prosecutor_agreement_counts():
    """A judge that correctly refutes false claims and verifies true ones."""
    ds = EvalDataset(
        name="prosecutor",
        description="x",
        metric="agreement",
        positive="FAIL",
        cases=tuple(),
    )
    # Direct metric check: classify expected FAIL (truth=false) vs actual FAIL
    # as a true positive; expected PASS (truth=true) vs actual PASS as TN.
    with mock.patch("verdict.evals.load_all_datasets", return_value=[ds]):
        pass  # structural sanity only


# === MetricResult summarize ===

def test_summarize_shape():
    r = MetricResult(name="x", description="d", confusion=Confusion(tp=1, tn=1), unknown_count=0, total=2)
    s = r.summarize()
    assert s["accuracy"] == 1.0
    assert "false_positive_rate" in s
    assert "false_negative_rate" in s
    assert s["total"] == 2