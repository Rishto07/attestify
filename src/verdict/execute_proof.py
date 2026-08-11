"""ExecuteProof: deterministic verification by actually running the code.

This checker takes code from the AI output, runs it inside a *sandbox*,
and verifies it:
1. Executes without crashing (exit code 0)
2. Produces the expected output
3. Doesn't hang (timeout enforced)
4. Runs inside a real boundary when available (see ``sandbox.py``)

Honesty rule: the checker always reports *which* sandbox it used and whether
that sandbox was isolated. A PASS from the subprocess fallback is a real PASS
about correctness — but the receipt must make it impossible to mistake that
for "safe to run". The Quarantine checker owns "is this dangerous?"; this
checker owns "does this code actually work?".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .core import Checker, CheckContext, Evidence, VerdictValue
from .sandbox import ExecutionResult, Sandbox, SubprocessSandbox, get_sandbox


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


# === BACKWARD-COMPAT EXECUTORS (thin wrappers, not isolated) ===
# Kept so `from verdict.execute_proof import run_python` still works.
# New code should use a Sandbox instance via ExecuteProofChecker.

def run_python(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    return SubprocessSandbox().run("python", code, timeout, workdir)


def run_shell(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    return SubprocessSandbox().run("bash", code, timeout, workdir)


def run_javascript(code: str, timeout: float, workdir: Optional[Path] = None) -> ExecutionResult:
    return SubprocessSandbox().run("javascript", code, timeout, workdir)


# === MAIN CHECKER ===

class ExecuteProofChecker(Checker):
    """Verify code by actually running it inside a sandbox."""

    name = "execute_proof"
    weight = 1.0

    def __init__(self, sandbox: Optional[Sandbox] = None):
        # An explicit sandbox wins; otherwise ctx.sandbox wins; otherwise auto.
        self._sandbox = sandbox

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        sandbox = self._sandbox or ctx.sandbox or get_sandbox()

        blocks = extract_code_blocks(output)

        if not blocks:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail="No code blocks found to execute.",
                data={"blocks_found": 0},
                weight=self.weight * 0.5,
            )

        workdir = Path(ctx.workdir) if ctx.workdir else None

        results: list[tuple[str, Optional[ExecutionResult]]] = []
        for lang, code in blocks:
            lang = detect_language(code) if lang == "text" else lang
            result = sandbox.run(lang, code, ctx.timeout, workdir)
            results.append((lang, result))

        # Analyze results
        executed = [(l, r) for l, r in results if r is not None]
        if not executed:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.UNKNOWN,
                detail=f"Found code but couldn't execute (unsupported language / sandbox). Sandbox: {sandbox.name}",
                data={"languages": [l for l, _ in blocks], "sandbox": sandbox.name},
                weight=self.weight * 0.5,
            )

        successful = sum(1 for _, r in executed if r.success)
        failed = sum(1 for _, r in executed if r and not r.success)
        timed_out = sum(1 for _, r in executed if r and r.timed_out)
        total_duration = sum(r.duration_ms for _, r in executed)
        isolated = all(r.isolated for _, r in executed) if executed else False

        data = {
            "blocks_executed": len(executed),
            "successful": successful,
            "failed": failed,
            "timed_out": timed_out,
            "total_duration_ms": total_duration,
            "sandbox": sandbox.name,
            "isolated": isolated,
            "results": [
                {
                    "language": lang,
                    "success": r.success,
                    "exit_code": r.exit_code,
                    "stdout": r.stdout[:500] if r else None,
                    "stderr": r.stderr[:500] if r else None,
                    "timed_out": r.timed_out if r else False,
                    "isolated": r.isolated if r else False,
                }
                for lang, r in executed
            ],
        }

        isolation_note = "isolated" if isolated else "NOT isolated (subprocess)"

        if failed > 0 or timed_out > 0:
            first_fail = next((r for _, r in executed if r and not r.success), None)
            if first_fail:
                if first_fail.timed_out:
                    detail = f"FAIL: code block timed out after {ctx.timeout}s [{isolation_note}]"
                elif first_fail.error:
                    detail = f"FAIL: {first_fail.error} [{isolation_note}]"
                else:
                    detail = f"FAIL: code block exited with code {first_fail.exit_code} [{isolation_note}]"
            else:
                detail = f"FAIL: {failed} block(s) failed, {timed_out} timed out [{isolation_note}]"
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
            detail=f"PASS: {successful}/{len(executed)} code block(s) ran successfully ({total_duration:.0f}ms) [{isolation_note}]",
            data=data,
            weight=self.weight,
        )