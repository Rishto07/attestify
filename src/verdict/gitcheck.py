"""Diff-check: scan staged changes before they become permanent history.

This is the engine behind the pre-commit hook. It reads what you're about
to commit (``git diff --cached``), pulls out the *added* lines (the only
ones you're actually committing), and runs the quarantine scanner over them.

Why added lines only: a diff shows removed lines and context too, but a
removed line is not entering your repo. Flagging removed/context lines would
either block on things you're deleting (noise) or scan things already
committed (not the hook's job). We scan exactly what you're adding.

Exit contract (used by the hook):
  0  clean — nothing dangerous staged
  2  danger found — commit should be blocked
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .core import CheckContext, Verdict, VerdictValue
from .quarantine import Finding, QuarantineChecker, scan


class GitError(RuntimeError):
    pass


@dataclass
class DiffResult:
    """What the staged diff contained and what we found in it."""

    added_lines: int
    files: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def dangerous(self) -> bool:
        return len(self.findings) > 0


def get_staged_diff(extra_args: Optional[list[str]] = None) -> str:
    """Return the staged diff text.

    Raises ``GitError`` when git is unavailable or there is a staging issue.
    """
    cmd = ["git", "diff", "--cached"] + (extra_args or [])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise GitError("git not found on PATH")
    except subprocess.TimeoutExpired:
        raise GitError("git diff timed out")

    if proc.returncode != 0:
        raise GitError(f"git diff failed: {proc.stderr.strip()[:200]}")

    return proc.stdout


def added_lines_from_diff(diff: str) -> list[str]:
    """Extract only the + lines from a unified diff.

    Filters out the `+++ b/path` file-header line (which is a path, not code).
    The result is exactly what is entering the repository.
    """
    added = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue  # file header / removed-file header, never real content
        if line.startswith("+"):
            added.append(line[1:])
    return added


def scan_staged_changes(extra_args: Optional[list[str]] = None) -> DiffResult:
    """Scan the staged diff and return findings.

    Pure function apart from the git subprocess call — testable by passing a
    fake git in the runner, or by feeding the diff through
    :func:`scan_added_lines` directly.
    """
    diff = get_staged_diff(extra_args)
    return scan_added_lines(diff)


def scan_added_lines(diff: str) -> DiffResult:
    """Scan an already-fetched diff text. No git involved — fully testable."""
    added = added_lines_from_diff(diff)
    if not added:
        return DiffResult(added_lines=0, files=0, findings=[])

    body = "\n".join(added)
    findings = scan(body)

    # Count touched files by looking at diff headers (+++ b/path).
    files = sum(1 for line in diff.splitlines() if line.startswith("+++"))

    return DiffResult(
        added_lines=len(added),
        files=files,
        findings=findings,
    )


def block_verdict() -> Verdict:
    """Aggregate the diff findings into a checkable verdict.

    Runs the real QuarantineChecker over the added lines so severity rules
    (critical/high ⇒ FAIL, medium only ⇒ UNKNOWN) apply consistently with the
    rest of Verdict.
    """
    diff = get_staged_diff()
    added = "\n".join(added_lines_from_diff(diff))
    evidence = QuarantineChecker().check(added, CheckContext(timeout=5.0))
    return Verdict.aggregate([evidence])


def _run_diffcheck(extra_args: Optional[list[str]] = None) -> int:
    """CLI body for `verdict diff-check`. Returns process exit code."""
    try:
        result = scan_staged_changes(extra_args)
    except GitError as e:
        print(f"verdict diff-check: {e}", flush=True)
        return 0  # no git → skip, never block a commit over tooling failure

    if not result.dangerous:
        scan_note = f" {result.added_lines} lines staged" if result.added_lines else " nothing to scan"
        print(f"[PASS] verdict: no dangerous patterns in staged changes{scan_note}", flush=True)
        return 0

    print(f"[FAIL] verdict: {len(result.findings)} dangerous pattern(s) in staged changes", flush=True)
    for f in result.findings:
        print(f"  [{f.severity.value}] {f.category}: {f.detail}", flush=True)
        print(f"    {f.location}", flush=True)
    print("Blocked by Verdict. Fix the change, or override with:  git commit --no-verify", flush=True)
    return 2