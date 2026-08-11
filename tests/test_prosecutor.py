"""Tests for storage module."""

import pytest
import tempfile
import os
from pathlib import Path

from verdict.core import Evidence, Receipt, Verdict, VerdictValue
from verdict.storage import ReceiptStore


class TestReceiptStore:
    @pytest.fixture
    def store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ReceiptStore(tmpdir)

    def test_save_and_load(self, store):
        evidence = [Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok")]
        verdict = Verdict.aggregate(evidence)
        receipt = Receipt.create("test output", verdict, "test-pipeline")

        path = store.save(receipt)
        assert path.exists()

        loaded = store.load(receipt.receipt_id)
        assert loaded is not None
        assert loaded.receipt_id == receipt.receipt_id
        assert loaded.verdict == "PASS"

    def test_load_nonexistent(self, store):
        result = store.load("nonexistent-id")
        assert result is None

    def test_query_by_verdict(self, store):
        # Save a few receipts
        for i in range(5):
            evidence = [Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok")]
            verdict = Verdict.aggregate(evidence)
            receipt = Receipt.create(f"output {i}", verdict, "pipeline")
            store.save(receipt)

        pass_results = list(store.query(verdict="PASS"))
        assert len(pass_results) == 5

    def test_stats(self, store):
        # Empty store
        stats = store.stats()
        assert stats["total_receipts"] == 0

        # Add receipts
        for i in range(3):
            evidence = [Evidence(checker="test", conclusion=VerdictValue.PASS, detail="ok")]
            verdict = Verdict.aggregate(evidence)
            receipt = Receipt.create(f"output {i}", verdict, "pipeline")
            store.save(receipt)

        stats = store.stats()
        assert stats["total_receipts"] == 3
        assert stats["by_verdict"]["PASS"] == 3