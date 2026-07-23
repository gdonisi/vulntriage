"""LLM client abstraction.

Every provider expose OpenAI-compatible chat completions endpoints,
so a single client implementation covers both. The base URL and
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
    # Accumulated prompt+completion tokens across all calls (best-effort;
    # mock/local clients without usage data may not expose this attribute).
    total_tokens: int

    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleClient:
    """Client for every LLM provider.

    Parameters
    ----------
    base_url:
        Endpoint URL for the provider.
    api_key:
        API key (``None`` / ``"none"`` for local providers).
    model:
        Model name forwarded in every request.
    reasoning_effort:
        Controls how much thinking / reasoning the model performs.
        Pass ``None`` (default) to disable reasoning entirely (the
        standard behaviour of non-reasoning models). Set to
        ``"low"``, ``"medium"``, or ``"high"``.  Provider support varies.
    local:
        ``True`` for self-hosted providers (lmstudio, ollama, llamacpp,
        vllm, custom with ``--local``), ``False`` for cloud providers
        (openai, openrouter, …). Used by ``--local-only`` to block cloud
        providers. Not used in the request path itself.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        model: str,
        reasoning_effort: str | None = None,
        local: bool,
        provider: str = "",
    ) -> None:
        self.model = model
        self.provider = provider
        self._reasoning_effort = reasoning_effort
        # Whether this provider is self-hosted (reserved for --local-only).
        self._local = local
        self._client = OpenAI(base_url=base_url, api_key=api_key or "none")
        # Best-effort running total of tokens consumed across all calls.
        self.total_tokens: int = 0

    def complete(self, system: str, user: str) -> str:
        start = time.perf_counter()
        kwargs: dict = {}
        if self._reasoning_effort is not None:
            kwargs["reasoning_effort"] = self._reasoning_effort
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
            **kwargs,
        )
        elapsed = time.perf_counter() - start
        content = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        if usage and getattr(usage, "total_tokens", None):
            self.total_tokens += usage.total_tokens
        toks = usage.total_tokens if usage and getattr(usage, "total_tokens", None) else "?"
        print(f"  [llm] model={self.model} {elapsed:.2f}s tokens={toks}")
        return content

    def list_models(self) -> list[str]:
        """Best-effort enumeration of models the provider exposes.

        Uses the OpenAI-compatible ``GET /models`` endpoint. Returns a sorted,
        deduped list of model id strings; on any error (endpoint missing,
        auth, transport) returns ``[]`` so callers can fall back to free text.
        """
        try:
            page = self._client.models.list()
        except Exception:  # noqa: BLE001 — best-effort; never raise
            return []
        ids: list[str] = []
        data = getattr(page, "data", None) or []
        for item in data:
            mid = (
                getattr(item, "id", None)
                or _nested(item, "body", "model")
                or _nested(item, "model")
            )
            if isinstance(mid, str) and mid:
                ids.append(mid)
        seen: set[str] = set()
        uniq = []
        for mid in sorted(ids):
            if mid not in seen:
                seen.add(mid)
                uniq.append(mid)
        return uniq


def _nested(obj: object, *path: str) -> str | None:
    cur: object = obj
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            cur = getattr(cur, key, None)
        if cur is None:
            return None
    return cur if isinstance(cur, str) else None


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


# ---------------------------------------------------------------------------
# Provider configuration
# --------------------------------------------------------------------------- #
#
# A single source of truth for per-provider connection details. Both
# ``make_client`` (chat completions) and ``list_models`` (model enumeration)
# route through `_provider_config` so they never disagree about the base URL
# or the local/cloud flag.
#
# Each value is (base_url, api_key, local). ``api_key`` is resolved lazily: a
# string means "read from env", ``None`` means "no auth (local)".


def _provider_config(
    provider: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    local: bool = False,
) -> tuple[str, str | None, bool]:
    """Return ``(base_url, api_key, local)`` for *provider*.

    Raises ``ValueError`` for unknown providers. Cloud providers read their
    key from the environment (raising if missing); local providers get a
    placeholder key. When *api_key* is passed explicitly it always takes
    precedence over the environment variable.

    The ``custom`` provider requires *base_url*; *api_key* and *local* are
    forwarded directly from the caller (``--api-key``, ``--local``).
    """
    p = provider.strip().lower()
    if p == "custom":
        if not base_url:
            raise ValueError("--base-url is required when --provider custom")
        return base_url, api_key, local
    if p == "lmstudio":
        return (
            os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234/v1"),
            api_key or os.environ.get("LMSTUDIO_API_KEY", "lm-studio"),
            True,
        )
    if p == "ollama":
        return (
            os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            api_key or os.environ.get("OLLAMA_API_KEY", "ollama"),
            True,
        )
    if p in {"llamacpp", "llama.cpp"}:
        return (
            os.environ.get("LLAMACPP_BASE_URL", "http://localhost:8080/v1"),
            api_key or os.environ.get("LLAMACPP_API_KEY", "llama.cpp"),
            True,
        )
    if p == "vllm":
        return (
            os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1"),
            api_key or os.environ.get("VLLM_API_KEY", "vllm"),
            True,
        )
    if p == "openai":
        return "https://api.openai.com/v1", api_key or _require_env("OPENAI_API_KEY"), False
    if p == "openrouter":
        return (
            "https://openrouter.ai/api/v1",
            api_key or _require_env("OPENROUTER_API_KEY"),
            False,
        )
    if p == "anthropic":
        return "https://api.anthropic.com/v1/", api_key or _require_env("ANTHROPIC_API_KEY"), False
    if p == "google":
        return (
            "https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key or _require_env("GEMINI_API_KEY"),
            False,
        )
    if p == "deepseek":
        return "https://api.deepseek.com", api_key or _require_env("DEEPSEEK_API_KEY"), False
    msg = (
        f"Unknown provider: {provider!r} "
        "(expected one of: 'custom', 'lmstudio', 'ollama', 'llamacpp', 'vllm', "
        "'openai', 'openrouter', 'anthropic', 'google', 'deepseek')"
    )
    raise ValueError(msg)


# Self-hosted providers (the same set that sets ``local=True`` on the client).
# Used by the CLI ``--local-only`` flag to block cloud providers.
# ``custom`` is NOT listed here — the caller passes ``--local`` explicitly
# and ``is_local_provider`` returns ``True`` for any custom provider with
# the local flag set (checked at the CLI/webapp layer, not here).
LOCAL_PROVIDERS = {"lmstudio", "ollama", "llamacpp", "vllm"}

# Friendly display names shown in the webapp dropdown (and usable anywhere
# a human-readable provider label is needed). Keys are the machine names
# used in `--provider`, `make_client`, and the CLI `choices` list.
PROVIDER_LABELS: dict[str, str] = {
    "lmstudio": "LM Studio",
    "ollama": "Ollama",
    "llamacpp": "llama.cpp",
    "vllm": "vLLM",
    "openai": "OpenAI",
    "openrouter": "OpenRouter",
    "anthropic": "Anthropic",
    "google": "Google",
    "deepseek": "DeepSeek",
    "custom": "Custom",
}


def is_local_provider(provider: str) -> bool:
    """Return True if *provider* is a self-hosted (local) provider.

    Note: for ``custom`` providers the local/cloud distinction is set at
    the caller level (``--local`` flag). This function only checks the
    hardcoded set.
    """
    return provider.strip().lower() in LOCAL_PROVIDERS


def make_client(
    provider: str,
    model: str,
    reasoning_effort: str | None = None,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    local: bool = False,
) -> LLMClient:
    """Factory that hides provider-specific connection details.

    Parameters
    ----------
    provider:
        API Provider. When set to ``"custom"``, *base_url* is required
        and *api_key* / *local* are forwarded directly.
    model:
        Model name to use.
    reasoning_effort:
        Reasoning/thinking level for supported models.
        ``None`` (default) = no reasoning (standard behaviour).
        Pass ``"low"``, ``"medium"``, or ``"high"`` to enable.
    base_url:
        Required when *provider* is ``"custom"``; ignored otherwise.
    api_key:
        Optional API key for ``custom`` providers; ignored otherwise.
    local:
        Whether a ``custom`` provider is self-hosted (``--local``); ignored
        for built-in providers (they hardcode their local flag).
    """
    resolved_url, resolved_key, resolved_local = _provider_config(
        provider, base_url=base_url, api_key=api_key, local=local
    )
    return OpenAICompatibleClient(
        base_url=resolved_url,
        api_key=resolved_key,
        model=model,
        reasoning_effort=reasoning_effort,
        local=resolved_local,
        provider=provider,
    )


def list_models(
    provider: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> list[str]:
    """Best-effort enumeration of a provider's available models.

    Routes through :class:`OpenAICompatibleClient` so the base URL and auth
    match ``make_client`` exactly. Returns a sorted, deduped list; on any
    connection/auth error returns ``[]`` so the model picker can fall back to
    free-text input without blocking the run.

    For ``custom`` providers, *base_url* and *api_key* are forwarded to
    ``_provider_config``.
    """
    resolved_url, resolved_key, resolved_local = _provider_config(
        provider, base_url=base_url, api_key=api_key
    )
    # An ephemeral client with a throwaway model name; ``list_models`` doesn't
    # open a chat completion, so the model isn't validated server-side.
    client = OpenAICompatibleClient(
        base_url=resolved_url,
        api_key=resolved_key,
        model="__list_models__",
        local=resolved_local,
    )
    return client.list_models()
