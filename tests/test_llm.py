"""Tests for LLM abstraction."""

import pytest

from verdict.llm import (
    get_llm,
    MockLLM,
    OpenAIClient,
    extract_json,
    LLMResult,
)


class TestMockLLM:
    def test_returns_canned_response(self):
        llm = MockLLM("I cannot verify this.")
        result = llm.complete("test prompt")
        assert result.text == "I cannot verify this."
        assert result.model == "mock"

    def test_custom_response(self):
        llm = MockLLM("custom response")
        result = llm.complete("prompt")
        assert result.text == "custom response"


class TestExtractJson:
    def test_direct_json(self):
        text = '{"verdict": "PASS", "confidence": 0.9}'
        assert extract_json(text) == {"verdict": "PASS", "confidence": 0.9}

    def test_fenced_json(self):
        text = '```json\n{"verdict": "FAIL"}\n```'
        result = extract_json(text)
        assert result is not None
        assert result["verdict"] == "FAIL"

    def test_trailing_json(self):
        text = 'Some text\n{"verdict": "PASS"}\nmore text'
        result = extract_json(text)
        assert result is not None

    def test_invalid_json(self):
        text = "This is not JSON at all"
        assert extract_json(text) is None


class TestGetLlm:
    def test_defaults_to_mock(self):
        llm = get_llm()
        assert isinstance(llm, MockLLM)

    def test_returns_mock_when_no_env(self):
        import os
        # Make sure no env vars are set
        orig_url = os.environ.pop("VERDICT_LLM_URL", None)
        orig_provider = os.environ.pop("VERDICT_LLM_PROVIDER", None)
        try:
            llm = get_llm()
            assert isinstance(llm, MockLLM)
        finally:
            if orig_url:
                os.environ["VERDICT_LLM_URL"] = orig_url
            if orig_provider:
                os.environ["VERDICT_LLM_PROVIDER"] = orig_provider