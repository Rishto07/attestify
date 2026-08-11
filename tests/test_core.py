"""Tests for core data model."""

import pytest

from verdict.core import (
    Evidence,
    Receipt,
    Verdict,
    VerdictValue,
    sha256_hex,
    CheckContext,
    Checker,
)


class TestVerdictValue:
    def test_pass(self):
        assert str(VerdictValue.PASS) == "PASS"

    def test_fail(self):
        assert str(VerdictValue.FAIL) == "FAIL"

    def test_unknown(self):
        assert str(VerdictValue.UNKNOWN) == "UNKNOWN"


class TestEvidence:
    def test_basic(self):
        e = Evidence(
            checker="test",
            conclusion=VerdictValue.PASS,
            detail="all good",
        )
        assert e.checker == "test"
        assert e.conclusion == VerdictValue.PASS

    def test_to_dict(self):
        e = Evidence(
            checker="test",
            conclusion=VerdictValue.FAIL,
            detail="broken",
            data={"key": "value"},
            weight=1.5,
        )
        d = e.to_dict()
        assert d["checker"] == "test"
        assert d["conclusion"] == "FAIL"
        assert d["data"] == {"key": "value"}


class TestVerdictAggregation:
    def test_all_pass(self):
        evidence = [
            Evidence(checker="a", conclusion=VerdictValue.PASS, detail="ok", weight=1.0),
            Evidence(checker="b", conclusion=VerdictValue.PASS, detail="ok", weight=1.0),
        ]
        v = Verdict.aggregate(evidence)
        assert v.value == VerdictValue.PASS
        assert v.confidence == 1.0

    def test_one_fail(self):
        evidence = [
            Evidence(checker="a", conclusion=VerdictValue.PASS, detail="ok", weight=1.0),
            Evidence(checker="b", conclusion=VerdictValue.FAIL, detail="broken", weight=1.0),
        ]
        v = Verdict.aggregate(evidence)
        assert v.value == VerdictValue.FAIL

    def test_all_unknown(self):
        evidence = [
            Evidence(checker="a", conclusion=VerdictValue.UNKNOWN, detail="?", weight=1.0),
            Evidence(checker="b", conclusion=VerdictValue.UNKNOWN, detail="?", weight=1.0),
        ]
        v = Verdict.aggregate(evidence)
        assert v.value == VerdictValue.UNKNOWN

    def test_empty(self):
        v = Verdict.aggregate([])
        assert v.value == VerdictValue.UNKNOWN

    def test_mixed_with_weights(self):
        # One strong FAIL should override weak PASS
        evidence = [
            Evidence(checker="a", conclusion=VerdictValue.PASS, detail="ok", weight=0.5),
            Evidence(checker="b", conclusion=VerdictValue.FAIL, detail="broken", weight=1.5),
        ]
        v = Verdict.aggregate(evidence, fail_threshold=1.0)
        assert v.value == VerdictValue.FAIL


class TestReceipt:
    def test_create(self):
        evidence = [
            Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok", weight=1.0),
        ]
        verdict = Verdict.aggregate(evidence)
        receipt = Receipt.create("test output", verdict, "test-pipeline", model="test-model")

        assert receipt.receipt_id
        assert receipt.input_hash == sha256_hex("test output")
        assert receipt.verdict == "PASS"
        assert receipt.pipeline == "test-pipeline"
        assert receipt.model == "test-model"
        assert receipt.signature

    def test_verify_signature(self):
        evidence = [Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok")]
        verdict = Verdict.aggregate(evidence)
        receipt = Receipt.create("test output", verdict, "pipeline")

        assert receipt.verify_signature()

    def test_verify_input(self):
        evidence = [Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok")]
        verdict = Verdict.aggregate(evidence)
        receipt = Receipt.create("test output", verdict, "pipeline")

        assert receipt.verify_input("test output")
        assert not receipt.verify_input("different output")


class TestCheckContext:
    def test_defaults(self):
        ctx = CheckContext()
        assert ctx.timeout == 10.0
        assert ctx.llm is None

    def test_with_llm(self):
        from verdict.llm import MockLLM

        llm = MockLLM()
        ctx = CheckContext(timeout=5.0, llm=llm, model="gpt-4")
        assert ctx.timeout == 5.0
        assert ctx.llm is llm
        assert ctx.model == "gpt-4"


class TestChecker:
    """Test that the Checker protocol works."""

    class DummyChecker(Checker):
        name = "dummy"
        weight = 1.0

        def check(self, output: str, ctx: CheckContext) -> Evidence:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.PASS,
                detail="dummy passed",
            )

    def test_checker_protocol(self):
        checker = self.DummyChecker()
        ctx = CheckContext()
        evidence = checker.check("test", ctx)
        assert evidence.checker == "dummy"
        assert evidence.conclusion == VerdictValue.PASS