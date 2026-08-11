"""Abstraction layer for LLM providers.

Verdict needs to call an LLM for the Prosecutor, but it deliberately has
*zero* hard dependencies on any specific LLM API. You bring your own
client (Ollama, OpenAI, Anthropic, anything OpenAI-compatible).

Design rule #1 again: no dependencies. The only thing this file imports
from third parties is ``json`` and ``time`` — everything else is stdlib.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


LLMResponse = str  # just the text


class LLMError(Exception):
    """Any provider-level failure."""
    pass


class TimeoutError(LLMError):
    """Took longer than the configured timeout."""
    pass


class RateLimitError(LLMError):
    """Hit a rate limit."""
    pass


class AuthError(LLMError):
    """Bad or missing API key."""
    pass


@dataclass
class LLMResult:
    """What a model returned, with metadata for observability."""

    text: str
    model: str
    finish_reason: str | None = None
    usage: dict[str, int] | None = None
    latency_ms: float | None = None

    @property
    def is_truncated(self) -> bool:
        return self.finish_reason in {"length", "max_tokens"}


class VerdictLLM(ABC):
    """Protocol that every LLM backend must implement."""

    @abstractmethod
    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResult:
        """Run a single completion."""
        raise NotImplementedError


class OpenAIClient(VerdictLLM):
    """OpenAI-compatible API client (OpenAI, Ollama, LiteLLM, etc).

    To use Ollama locally::

        export VERDICT_LLM_URL=http://localhost:11434/v1
        export VERDICT_LLM_KEY=ollama  # any string, Ollama ignores it

    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = (base_url or self._env("VERDICT_LLM_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or self._env("VERDICT_LLM_KEY", "")
        self.timeout = timeout

    @staticmethod
    def _env(name: str, default: str) -> str:
        import os
        return os.environ.get(name, default)

    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResult:
        model = model or self._env("VERDICT_LLM_MODEL", "gpt-4o-mini")
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        import time

        start = time.perf_counter()
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RateLimitError(f"Rate limited: {e.reason}") from e
            if e.code in {401, 403}:
                raise AuthError(f"Auth failed: {e.reason}") from e
            raise LLMError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"Connection failed: {e.reason}") from e

        latency = (time.perf_counter() - start) * 1000
        choice = data["choices"][0]
        return LLMResult(
            text=choice["message"]["content"],
            model=data.get("model", model),
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage"),
            latency_ms=latency,
        )


class MockLLM(VerdictLLM):
    """A deterministic mock for testing and offline demos.

    Returns a canned response, but does not require an API key or network.
    """

    def __init__(self, response: str = "I cannot verify this claim."):
        self.response = response

    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> LLMResult:
        return LLMResult(
            text=self.response,
            model="mock",
            finish_reason="stop",
        )


def get_llm() -> VerdictLLM:
    """Auto-detect the best available LLM client.

    Priority:
    1. VERDICT_LLM_URL set → OpenAIClient
    2. VERDICT_LLM_PROVIDER=ollama → OpenAIClient pointing at localhost
    3. Otherwise → MockLLM (failsafe)
    """
    import os
    url = os.environ.get("VERDICT_LLM_URL", "")
    if url:
        return OpenAIClient()

    provider = os.environ.get("VERDICT_LLM_PROVIDER", "").lower()
    if provider == "ollama":
        return OpenAIClient(base_url="http://localhost:11434/v1", api_key="ollama")

    return MockLLM()


def extract_json(text: str) -> dict | None:
    """Try to extract JSON from model output.

    Models are terrible at outputting raw JSON (they escape, quote, add
    markdown fences). This tries a few common patterns, falling back to None.
    """
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try fenced
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try trailing braces from first { to last }
    if "{" in text and "}" in text:
        start = text.find("{")
        # find matching close
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break

    return None