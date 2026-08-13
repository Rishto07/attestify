"""Receipt storage — JSONL-based, git-friendly, auditable.

Every attestify produces a receipt. This module stores them in a simple way:
one JSONL file per day, line-oriented, append-only. This makes it:
- Greppable (grep for receipts from a specific day)
- Git-digestible (receipts are small text files)
- Audit-friendly (you can replay any receipt)

The storage format is intentionally simple. No database required.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .core import Receipt, _canonical_json


def _today_filename() -> str:
    """Filename for today's receipts: receipts-2026-08-11.jsonl"""
    return f"receipts-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


class ReceiptStore:
    """Append-only JSONL receipt storage."""

    def __init__(self, path: str | Path | None = None):
        """
        Args:
            path: Directory to store receipts. Defaults to ./attestify-data in cwd,
                  or ATTESTIFY_DATA_DIR env var.
        """
        if path is None:
            path = os.environ.get("ATTESTIFY_DATA_DIR", "attestify-data")
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

    def _filepath(self, date: Optional[str] = None) -> Path:
        """Path to the receipt file for a given date (YYYY-MM-DD)."""
        if date is None:
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.path / f"receipts-{date}.jsonl"

    def save(self, receipt: Receipt) -> Path:
        """Append a receipt to today's file. Returns the file path."""
        filepath = self._filepath()
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(receipt.to_json() + "\n")
        return filepath

    def load(self, receipt_id: str) -> Optional[Receipt]:
        """Load a receipt by ID. Searches today's file first, then recent files."""
        # Search in reverse chronological order
        dates = []
        for f in sorted(self.path.glob("receipts-*.jsonl"), reverse=True):
            # Extract date from filename
            date = f.stem.replace("receipts-", "")
            dates.append((date, f))
            if len(dates) >= 7:  # search last 7 days
                break

        for _, filepath in dates:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("receipt_id") == receipt_id:
                            return Receipt.from_dict(data)
                    except json.JSONDecodeError:
                        continue
        return None

    def query(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        attestify: Optional[str] = None,
        limit: int = 100,
    ) -> Iterable[Receipt]:
        """Query receipts by date range and/or attestify.

        Args:
            start_date: Start date (YYYY-MM-DD), inclusive
            end_date: End date (YYYY-MM-DD), inclusive
            attestify: Filter by "PASS", "FAIL", or "UNKNOWN"
            limit: Maximum receipts to return

        Yields:
            Receipt objects in reverse chronological order
        """
        # Build list of files to search
        files = sorted(self.path.glob("receipts-*.jsonl"), reverse=True)

        count = 0
        for filepath in files:
            date = filepath.stem.replace("receipts-", "")
            if start_date and date < start_date:
                continue
            if end_date and date > end_date:
                continue

            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    if count >= limit:
                        return
                    try:
                        data = json.loads(line)
                        if attestify and data.get("attestify") != attestify:
                            continue
                        yield Receipt.from_dict(data)
                        count += 1
                    except (json.JSONDecodeError, KeyError):
                        continue

    def recent(self, n: int = 10) -> Iterable[Receipt]:
        """Get the n most recent receipts."""
        return self.query(limit=n)

    def stats(self) -> dict:
        """Get storage statistics."""
        files = list(self.path.glob("receipts-*.jsonl"))
        total_receipts = 0
        by_attestify = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0}

        for filepath in files:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        total_receipts += 1
                        v = data.get("attestify")
                        if v in by_attestify:
                            by_attestify[v] += 1
                    except json.JSONDecodeError:
                        continue

        return {
            "total_receipts": total_receipts,
            "files": len(files),
            "by_attestify": by_attestify,
            "oldest_file": min(files).name if files else None,
            "newest_file": max(files).name if files else None,
        }

    def export(self, receipt_ids: list[str], output_path: Path) -> int:
        """Export specific receipts to a single JSON file."""
        receipts = []
        for rid in receipt_ids:
            r = self.load(rid)
            if r:
                receipts.append(r.to_dict())

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"receipts": receipts}, f, indent=2)

        return len(receipts)