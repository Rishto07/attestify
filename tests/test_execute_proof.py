"""Tests for ExecuteProof checker."""

import pytest

from verdict.core import CheckContext, VerdictValue
from verdict.execute_proof import (
    ExecuteProofChecker,
    extract_code_blocks,
    detect_language,
    run_python,
)


class TestExtractCodeBlocks:
    def test_fenced_python(self):
        text = "```python\nprint('hello')\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0][0] == "python"
        assert "print('hello')" in blocks[0][1]

    def test_fenced_javascript(self):
        text = "```js\nconst x = 1;\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0][0] == "javascript"

    def test_no_code(self):
        text = "This is just plain text with no code."
        blocks = extract_code_blocks(text)
        assert len(blocks) == 0

    def test_multiple_blocks(self):
        text = "```python\nx = 1\n```\n\nSome text\n\n```bash\necho hi\n```"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2


class TestDetectLanguage:
    def test_python(self):
        code = "def hello():\n    return 'hello'"
        assert detect_language(code) == "python"

    def test_javascript(self):
        code = "const x = () => { return 1; };"
        assert detect_language(code) == "javascript"

    def test_shell(self):
        code = "#!/bin/bash\necho hello"
        assert detect_language(code) == "bash"

    def test_unknown(self):
        code = "some random text"
        assert detect_language(code) == "text"


class TestRunPython:
    def test_successful(self):
        result = run_python("print('hello')", timeout=5.0)
        assert result.success
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_syntax_error(self):
        result = run_python("def broken(", timeout=5.0)
        assert not result.success
        assert result.exit_code != 0

    def test_timeout(self):
        import pytest
        result = run_python("while True: pass", timeout=0.5)
        assert result.timed_out
        assert not result.success


class TestExecuteProofChecker:
    def test_pass_valid_code(self):
        checker = ExecuteProofChecker()
        ctx = CheckContext(timeout=5.0)
        code = "```python\nprint('test')\n```"
        evidence = checker.check(code, ctx)
        assert evidence.conclusion == VerdictValue.PASS

    def test_fail_syntax_error(self):
        checker = ExecuteProofChecker()
        ctx = CheckContext(timeout=5.0)
        code = "```python\ndef broken(\n```"
        evidence = checker.check(code, ctx)
        assert evidence.conclusion == VerdictValue.FAIL

    def test_unknown_no_code(self):
        checker = ExecuteProofChecker()
        ctx = CheckContext(timeout=5.0)
        evidence = checker.check("Just some text", ctx)
        assert evidence.conclusion == VerdictValue.UNKNOWN

    def test_timeout(self):
        checker = ExecuteProofChecker()
        ctx = CheckContext(timeout=0.5)
        code = "```python\nwhile True: pass\n```"
        evidence = checker.check(code, ctx)
        assert evidence.conclusion == VerdictValue.FAIL
        assert "timed out" in evidence.detail.lower()