"""LLM client abstraction.

Both LM Studio and OpenRouter expose OpenAI-compatible chat completions
endpoints, so a single client implementation covers both. The base URL and
API key differ per provider; the model name is passed per call.
"""

from __future__ import annotations

import os
import time
from typing import Protocol

from openai import OpenAI


class LLMClient(Protocol):
    """Minimal interface every pipeline module relies on."""

    model: str

    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleClient:
    """One client for both LM Studio and OpenRouter.

    LM Studio:  base_url=http://localhost:1234/v1, api_key="lm-studio"
    OpenRouter: base_url=https://openrouter.ai/api/v1, api_key from env
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        model: str,
    ) -> None:
        self.model = model
        self._client = OpenAI(base_url=base_url, api_key=api_key or "none")

    def complete(self, system: str, user: str) -> str:
        start = time.perf_counter()
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )
        elapsed = time.perf_counter() - start
        content = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        print(
            f"  [llm] model={self.model} {elapsed:.2f}s "
            f"tokens={usage.total_tokens if usage else '?'}"
        )
        return content


def make_client(provider: str, model: str) -> LLMClient:
    """Factory that hides provider-specific connection details."""
    if provider == "lmstudio":
        return OpenAICompatibleClient(
            base_url=os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234/v1"),
            api_key="lm-studio",
            model=model,
        )
    if provider == "openrouter":
        return OpenAICompatibleClient(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            model=model,
        )
    msg = f"Unknown provider: {provider!r} (expected 'lmstudio' or 'openrouter')"
    raise ValueError(msg)
