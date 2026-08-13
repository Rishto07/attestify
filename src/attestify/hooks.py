#!/usr/bin/env python
"""Git pre-commit hook installer for Verdict.

``attestify hook install`` copies a dependency-free POSIX-sh hook into
``.git/hooks/pre-commit``. The hook runs ``attestify diff-check`` against your
staged changes and blocks the commit on dangerous patterns.

The hook itself is stored as a string constant (``HOOK_TEMPLATE``) so it ships
inside the installed package - no separate file to go missing. It is plain
POSIX sh on purpose: the git hook must work even if Python itself is broken,
and it must never be the thing that crashes your commit.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

HOOK_NAME = "pre-commit"

# The sh script written to .git/hooks/pre-commit. Keep it POSIX-only:
# git hooks run under /bin/sh, not bash, and must be sturdy.
HOOK_TEMPLATE = r"""#!/bin/sh
# Verdict pre-commit hook: blocks commits that stage dangerous AI output.
# Installed by `attestify hook install`. Bypass on purpose: git commit --no-verify
if command -v attestify >/dev/null 2>&1; then
    VERDICT_CMD="attestify"
elif command -v python  >/dev/null 2>&1; then
    VERDICT_CMD="python -m attestify"
elif command -v python3 >/dev/null 2>&1; then
    VERDICT_CMD="python3 -m attestify"
else
    echo "attestify: not found; skipping pre-commit check" >&2
    exit 0
fi

if [ "${ATTESTIFY_SKIP:-}" = "1" ]; then
    echo "attestify: skipped via ATTESTIFY_SKIP=1" >&2
    exit 0
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    exit 0  # not a git repo; never block
fi

FOUND=$($VERDICT_CMD diff-check 2>/dev/null)
RC=$?

if [ "$RC" -eq 2 ]; then
    echo "$FOUND"
    echo "attestify: BLOCKED - dangerous pattern in staged changes."
    echo "         Fix it, or override deliberately:  git commit --no-verify"
    exit 1
fi

exit 0
"""


def find_git_dir(start: Optional[Path] = None) -> Optional[Path]:
    """Resolve the repository's .git directory (supports worktrees)."""
    cur = (start or Path.cwd()).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=cur,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    git_dir = Path(out.stdout.strip())
    if git_dir.is_absolute():
        return git_dir
    return (cur / git_dir).resolve()


def hooks_dir(start: Optional[Path] = None) -> Optional[Path]:
    git_dir = find_git_dir(start)
    return (git_dir / "hooks") if git_dir else None


def install(start: Optional[Path] = None) -> bool:
    """Write the hook into .git/hooks/pre-commit.

    Returns True when a Verdict hook is now present. Never touches an existing
    hook that isn't ours - overwriting another tool's security hook would be
    exactly the uninvited change Verdict exists to prevent.
    """
    hd = hooks_dir(start)
    if hd is None:
        raise RuntimeError("not a git repository - can't install a hook here")

    hd.mkdir(parents=True, exist_ok=True)
    target = hd / HOOK_NAME

    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="ignore")
        if "Verdict pre-commit hook" in existing:
            print(f"attestify: hook already installed at {target}")
            return True
        # A foreign hook (husky, pre-commit framework, a secrets scanner...).
        # Overwriting another tool's security hook would be exactly the kind
        # of uninvited change Verdict exists to prevent. Refuse.
        print(f"attestify: {target} exists and is not a Verdict hook; leaving it alone")
        print("        move it aside (or uninstall it) first, then re-run hook install")
        return False

    target.write_text(HOOK_TEMPLATE, encoding="utf-8")
    # Mark executable (best effort; on Windows this is a no-op).
    try:
        target.chmod(0o755)
    except OSError:
        pass
    print(f"attestify: pre-commit hook installed -> {target}")
    print("        next commit will auto-check staged changes for danger")
    return True


def uninstall(start: Optional[Path] = None) -> bool:
    """Remove a Verdict hook we installed. Leave foreign hooks alone."""
    hd = hooks_dir(start)
    if hd is None:
        return False
    target = hd / HOOK_NAME
    if not target.exists():
        print("attestify: no hook installed")
        return True
    text = target.read_text(encoding="utf-8", errors="ignore")
    if "Verdict pre-commit hook" not in text:
        print(f"attestify: {target} is not a Verdict hook; not removing it")
        return False
    target.unlink()
    print(f"attestify: removed {target}")
    return True


def status(start: Optional[Path] = None) -> int:
    """Report hook installation state. Returns 0 installed, 1 not, 2 foreign."""
    hd = hooks_dir(start)
    if hd is None:
        print("attestify: not a git repository")
        return 2
    target = hd / HOOK_NAME
    if not target.exists():
        print("attestify: no pre-commit hook installed")
        return 1
    text = target.read_text(encoding="utf-8", errors="ignore")
    if "Verdict pre-commit hook" in text:
        print(f"attestify: pre-commit hook installed -> {target}")
        return 0
    print(f"attestify: a non-Verdict pre-commit hook exists at {target}")
    return 2