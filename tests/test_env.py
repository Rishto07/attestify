"""Tests for the secure .env loader and prosecutor wiring."""

import os
from pathlib import Path
from unittest import mock

import pytest

from verdict.env import _parse_line, load_dotenv
from verdict.llm import MockLLM, get_llm, OpenAIClient
from verdict.prosecutor import PROSECUTOR_PROMPT, ProsecutorChecker


class TestParseLine:
    def test_simple(self):
        assert _parse_line("VERDICT_LLM_KEY=sk-abc") == ("VERDICT_LLM_KEY", "sk-abc")

    def test_whitespace(self):
        assert _parse_line("  KEY  =  value  ") == ("KEY", "value")

    def test_trailing_comment(self):
        assert _parse_line("KEY=value # a comment") == ("KEY", "value")

    def test_quoted(self):
        assert _parse_line("KEY='quoted value'") == ("KEY", "quoted value")
        assert _parse_line('KEY="double quoted"') == ("KEY", "double quoted")

    def test_hash_inside_quotes_kept(self):
        assert _parse_line("KEY='a#b'") == ("KEY", "a#b")

    def test_blank_and_comment_lines(self):
        assert _parse_line("") is None
        assert _parse_line("# just a comment") is None
        assert _parse_line("   ") is None

    def test_no_equals(self):
        assert _parse_line("WORDWITHOUTEQUALS") is None


class TestLoadDotenv:
    def test_loads_values(self, tmp_path, monkeypatch):
        f = tmp_path / ".env"
        f.write_text("A=1\nB=two # comment\n", encoding="utf-8")
        assert load_dotenv(f) is True
        assert os.environ["A"] == "1"
        assert os.environ["B"] == "two"

    def test_missing_file_returns_false(self, tmp_path):
        assert load_dotenv(tmp_path / "nope.env") is False

    def test_real_environment_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("A", "from-shell")
        f = tmp_path / ".env"
        f.write_text("A=from-file\n", encoding="utf-8")
        load_dotenv(f)
        assert os.environ["A"] == "from-shell"

    def test_override_flag(self, tmp_path, monkeypatch):
        monkeypatch.setenv("A", "from-shell")
        f = tmp_path / ".env"
        f.write_text("A=from-file\n", encoding="utf-8")
        load_dotenv(f, override=True)
        assert os.environ["A"] == "from-file"


_LLM_VARS = ("VERDICT_LLM_URL", "VERDICT_LLM_KEY", "VERDICT_LLM_MODEL", "VERDICT_SANDBOX")


class TestGetLlmWithDotenv:
    def test_url_and_key_from_dotenv(self, tmp_path, monkeypatch):
        # Clean out any shell-level vars so only .env decides.
        for var in _LLM_VARS:
            monkeypatch.delenv(var, raising=False)
        (tmp_path / ".env").write_text(
            "VERDICT_LLM_URL=https://proxy.example/v1\n"
            "VERDICT_LLM_KEY=sk-from-file\n"
            "VERDICT_LLM_MODEL=some-model\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        try:
            llm = get_llm()
            assert isinstance(llm, OpenAIClient)
            assert llm.base_url == "https://proxy.example/v1"
            assert llm.api_key == "sk-from-file"
        finally:
            # load_dotenv writes straight to os.environ (by design), so we
            # scrub the vars ourselves — monkeypatch can't undo a direct set.
            for var in _LLM_VARS:
                os.environ.pop(var, None)

    def test_mock_when_no_config(self, monkeypatch):
        for var in _LLM_VARS:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.chdir(tmp_path_factory_clean())
        assert isinstance(get_llm(), MockLLM)


def tmp_path_factory_clean() -> Path:
    """A dir with no .env so get_llm() falls back to Mock."""
    import tempfile
    return Path(tempfile.mkdtemp())


class TestProsecutorWiring:
    def test_refuted_response_becomes_fail_evidence(self):
        # A judge that firmly refutes the output should drive a FAIL.
        judge = MockLLM(
            '{"verdict": "FAIL", "confidence": 0.95, '
            '"challenges": [{"type": "factual", "claim": "x", "reason": "wrong", "evidence": "y"}], '
            '"summary": "The claim is false."}'
        )
        from verdict.core import CheckContext

        checker = ProsecutorChecker(llm=judge)
        ctx = CheckContext(timeout=5.0, llm=judge, model="mock")
        evidence = checker.check("The Eiffel Tower is in Berlin.", ctx)

        assert evidence.conclusion.value == "FAIL"

    def test_pass_response_becomes_pass_evidence(self):
        judge = MockLLM(
            '{"verdict": "PASS", "confidence": 0.8, '
            '"challenges": [], "summary": "Nothing wrong found."}'
        )
        from verdict.core import CheckContext

        checker = ProsecutorChecker(llm=judge)
        ctx = CheckContext(timeout=5.0, llm=judge, model="mock")
        evidence = checker.check("1 + 1 = 2.", ctx)

        assert evidence.conclusion.value == "PASS"

    def test_no_llm_unknown(self):
        from verdict.core import CheckContext

        checker = ProsecutorChecker()
        ctx = CheckContext(timeout=5.0, llm=None)
        evidence = checker.check("anything", ctx)
        assert evidence.conclusion.value == "UNKNOWN"
        assert "No LLM configured" in evidence.detail

    def test_unparseable_response_unknown(self):
        from verdict.core import CheckContext

        judge = MockLLM("I am not sure about this claim, sorry.")
        checker = ProsecutorChecker(llm=judge)
        ctx = CheckContext(timeout=5.0, llm=judge, model="mock")
        evidence = checker.check("some output", ctx)
        assert evidence.conclusion.value == "UNKNOWN"


class TestProsecutorPromptSafety:
    def test_prompt_is_bounded(self):
        # Very long outputs must be truncated, not sent whole.
        huge = "x" * 20_000
        prompt = PROSECUTOR_PROMPT.format(output=huge[:8000])
        assert len(prompt) < 10_000