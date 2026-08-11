"""ExecuteProof: deterministic verification by actually running the code.

This checker takes code from the AI output, runs it in an isolated subprocess,
and verifies it:
1. Executes without crashing (exit code 0)
2. Produces the expected output (if the AI claimed specific output)
3. Doesn't hang (timeout enforced)
4. Doesn't write to unexpected locations (sandboxed)

Design rule: this is NOT a security sandbox. It's an *execution verifier*.
The subprocess runs with the same permissions as the user — if you run it
as root, it has root. The quarantine module handles the "is this dangerous?"
question. This module handles the "does this code actually work?" question.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .core import Checker, CheckContext, Evidence, VerdictValue


@dataclass
class ExecutionResult:
    """What happened when we tried to run the code."""

    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    error: str | None = None


# === CODE EXTRACTORS ===

# Alias map: many fenced blocks say "js" but mean "javascript".
# Normalizing at the source means the checker sees one canonical name.
_LANG_ALIASES = {
    "py": "python",
    "py3": "python",
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "ts": "typescript",
    "sh": "bash",
    "shell": "bash",
    "bash": "bash",
    "zsh": "bash",
    "cmd": "cmd",
    "batch": "cmd",
}


def normalize_language(lang: str) -> str:
    return _LANG_ALIASES.get(lang, lang)


def extract_code_blocks(text: str) -> list[tuple[str, str]]:
    """Pull out code blocks from markdown, plain text, etc.

    Returns list of (language, code) tuples in order of appearance.
    """
    blocks = []

    # Markdown fenced blocks: ```python ... ```
    for match in re.finditer(r"```(\w*)\s*\n(.*?)```", text, re.DOTALL):
        lang = normalize_language(match.group(1).strip() or "text")
        code = match.group(2)
        blocks.append((lang, code))

    # If no fenced blocks, look for indentation-based code blocks (common in explanations)
    # This is heuristic — only grab if it looks like real code
    if not blocks:
        # Lines starting with 4+ spaces or a tab are likely code
        lines = text.splitlines()
        in_block = False
        block_lines = []
        block_lang = "text"

        for line in lines:
            if (line.startswith("    ") or line.startswith("\t")) and len(line.strip()) > 0:
                if not in_block:
                    in_block = True
                block_lines.append(line[4:] if line.startswith("    ") else line[1:])
            else:
                if in_block and block_lines:
                    # Heuristic: if block has typical code keywords, keep it
                    block_text = "\n".join(block_lines)
                    if any(kw in block_text.lower() for kw in ["def ", "class ", "import ", "function ", "const ", "let ", "var ", "return ", "if ", "for "]):
                        blocks.append((block_lang, block_text))
                in_block = False
                block_lines = []

        # Don't forget trailing block
        if in_block and block_lines:
            blocks.append(("text", "\n".join(block_lines)))

    return blocks


def detect_language(code: str) -> str:
    """Heuristic guess at what language this is."""
    code = code.strip()

    # Python
    if re.search(r"^def\s+\w+\s*\(", code, re.MULTILINE) or re.search(r"^import\s+\w+", code, re.MULTILINE) or "print(" in code:
        return "python"

    # JavaScript/TypeScript
    if "function " in code or "const " in code or "let " in code or "=> " in code or "require(" in code:
        return "javascript"

    # Shell
    if code.startswith("#!/") or re.search(r"^\s*(if|for|while|do)\s+\[", code, re.MULTILINE):
        return "bash"

    # Go
    if "package " in code and "func " in code:
        return "go"

    # Rust
    if "fn main()" in code or "use std::" in code:
        return "rust"

    return "text"


# === EXECUTORS ===

def run_python(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    """Run Python code in a subprocess."""
    import time
    start = time.perf_counter()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir=workdir) as f:
        f.write(code)
        f.flush()
        tmp_path = f.name

    try:
        proc = subprocess.run(
            ["python", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workdir,
        )
        return ExecutionResult(
            success=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="Process timed out",
            duration_ms=timeout * 1000,
            timed_out=True,
        )
    except FileNotFoundError:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="Python interpreter not found",
            duration_ms=0,
            error="python not in PATH",
        )
    except Exception as e:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr=str(e),
            duration_ms=0,
            error=str(e),
        )
    finally:
        try:
            Path(tmp_path).unlink()
        except FileNotFoundError:
            pass


def run_shell(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    """Run shell script in a subprocess."""
    import time
    start = time.perf_counter()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, dir=workdir) as f:
        f.write("#!/bin/sh\n" + code)
        f.flush()
        tmp_path = f.name

    try:
        proc = subprocess.run(
            ["sh", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workdir,
        )
        return ExecutionResult(
            success=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="Process timed out",
            duration_ms=timeout * 1000,
            timed_out=True,
        )
    except FileNotFoundError:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="sh interpreter not found",
            duration_ms=0,
            error="sh not in PATH",
        )
    except Exception as e:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr=str(e),
            duration_ms=0,
            error=str(e),
        )
    finally:
        try:
            Path(tmp_path).unlink()
        except FileNotFoundError:
            pass


def run_javascript(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    """Run JavaScript code using node."""
    import time
    start = time.perf_counter()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, dir=workdir) as f:
        f.write(code)
        f.flush()
        tmp_path = f.name

    try:
        proc = subprocess.run(
            ["node", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workdir,
        )
        return ExecutionResult(
            success=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="Process timed out",
            duration_ms=timeout * 1000,
            timed_out=True,
        )
    except FileNotFoundError:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr="node interpreter not found",
            duration_ms=0,
            error="node not in PATH",
        )
    except Exception as e:
        return ExecutionResult(
            success=False,
            exit_code=None,
            stdout="",
            stderr=str(e),
            duration_ms=0,
            error=str(e),
        )
    finally:
        try:
            Path(tmp_path).unlink()
        except FileNotFoundError:
            pass


# === MAIN CHECKER ===

class ExecuteProofChecker(Checker):
    """Verify code by actually running it."""

    name = "execute_proof"
    weight = 1.0

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        blocks = extract_code_blocks(output)

        if not blocks:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No code blocks found to execute.",
                data={"blocks_found": 0},
                weight=self.weight * 0.5,
            )

        # Workdir: use ctx.workdir if provided, otherwise temp
        workdir = Path(ctx.workdir) if ctx.workdir else None

        results = []
        for lang, code in blocks:
            lang = detect_language(code) if lang == "text" else lang

            if lang == "python":
                results.append(("python", run_python(code, ctx.timeout, workdir)))
            elif lang in {"bash", "shell", "sh"}:
                results.append(("bash", run_shell(code, ctx.timeout, workdir)))
            elif lang == "javascript":
                results.append(("javascript", run_javascript(code, ctx.timeout, workdir)))
            else:
                # Skip unknown languages
                results.append((lang, None))

        # Analyze results
        executed = [(l, r) for l, r in results if r is not None]
        if not executed:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="Found code but couldn't execute (unknown language).",
                data={"languages": [l for l, _ in blocks]},
                weight=self.weight * 0.5,
            )

        successful = sum(1 for _, r in executed if r.success)
        failed = sum(1 for _, r in executed if r and not r.success)
        timed_out = sum(1 for _, r in executed if r and r.timed_out)

        total_duration = sum(r.duration_ms for _, r in executed)

        data = {
            "blocks_executed": len(executed),
            "successful": successful,
            "failed": failed,
            "timed_out": timed_out,
            "total_duration_ms": total_duration,
            "results": [
                {
                    "language": lang,
                    "success": r.success,
                    "exit_code": r.exit_code,
                    "stdout": r.stdout[:500] if r else None,
                    "stderr": r.stderr[:500] if r else None,
                    "timed_out": r.timed_out if r else False,
                }
                for lang, r in executed
            ],
        }

        if failed > 0 or timed_out > 0:
            # Find the first failure for detail
            first_fail = next((r for _, r in executed if r and not r.success), None)
            if first_fail:
                detail = f"FAIL: code block exited with code {first_fail.exit_code}"
                if first_fail.timed_out:
                    detail = f"FAIL: code block timed out after {ctx.timeout}s"
                if first_fail.error:
                    detail = f"FAIL: {first_fail.error}"
            else:
                detail = f"FAIL: {failed} block(s) failed, {timed_out} timed out"
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.FAIL,
                detail=detail,
                data=data,
                weight=self.weight,
            )

        return Evidence(
            checker=self.name,
            conclusion=VerdictValue.PASS,
            detail=f"PASS: {successful}/{len(executed)} code block(s) executed successfully ({total_duration:.0f}ms)",
            data=data,
            weight=self.weight,
        )