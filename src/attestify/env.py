"""Tiny, dependency-free .env loader.

We deliberately *do not* depend on python-dotenv, for the same reason the
whole project has zero runtime dependencies: a trust tool should not hand
your secrets to a dependency graph you haven't audited.

Rules:
- Looks for ``.env`` in the current working directory (or ``ATTESTIFY_ENV_FILE``).
- Keys already set in the real environment win (shell beats file).
- Lines: ``KEY=VALUE``, trailing ``# comments`` (value-safe inside quotes),
  blank lines ignored, ``KEY=`value`` and ``KEY="value"`` unquoted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_MISSING = object()


def _parse_line(line: str) -> Optional[tuple[str, str]]:
    """Parse one .env line into (KEY, VALUE). None when not a setting."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "=" not in line:
        return None

    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()

    # Strip a trailing comment, but not one inside quotes.
    if value:
        in_quote = None
        for i, ch in enumerate(value):
            if ch in {"'", '"'}:
                in_quote = in_quote if in_quote else ch
                if in_quote and ch == in_quote and i > 0:
                    in_quote = None
            elif ch == "#" and not in_quote:
                value = value[:i]
                break

    value = value.strip()
    # Unquote
    if len(value) >= 2 and value[0] == value[-1] == "'":
        value = value[1:-1]
    elif len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]

    return key, value


def load_dotenv(
    path: Optional[str | Path] = None,
    override: bool = False,
) -> bool:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Args:
        path: Explicit env file. Defaults to ``.env`` in cwd, or
            ``$ATTESTIFY_ENV_FILE``.
        override: When True, file values overwrite existing env vars.
            Default False — real environment wins.

    Returns:
        True when a file was found and loaded.
    """
    if path is None:
        path = os.environ.get("ATTESTIFY_ENV_FILE", ".env")
    p = Path(path)
    if not p.exists():
        return False

    changed = 0
    for raw in p.read_text(encoding="utf-8").splitlines():
        parsed = _parse_line(raw)
        if parsed is None:
            continue
        key, value = parsed
        if not override and os.environ.get(key, _MISSING) is not _MISSING:
            continue  # real environment already wins
        os.environ[key] = value
        changed += 1

    return changed > 0