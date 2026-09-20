"""LLM provider adapters over plain HTTPS (httpx). No vendor SDKs, so switching providers is a
configuration change (LLM_PROVIDER / LLM_MODEL / LLM_API_KEY / LLM_BASE_URL).

Keys are read from settings only, sent in headers (never in URLs or logs), and never included in
error messages.
"""
from __future__ import annotations

import logging

import httpx

from soar.config import Settings, get_settings

log = logging.getLogger("ai.llm")

DEFAULT_MODELS = {"gemini": "gemini-2.0-flash", "openai": "gpt-4o-mini", "ollama": "llama3.1",
                  "openai_compatible": "default", "anthropic": "claude-haiku-4-5-20251001"}
DEFAULT_BASE = {"openai": "https://api.openai.com/v1", "ollama": "http://localhost:11434/v1"}
NEEDS_KEY = {"gemini", "openai", "anthropic"}


class LLMNotConfigured(RuntimeError):
    pass


class LLMError(RuntimeError):
    pass


class Provider:
    name = "base"

    def __init__(self, model: str, key: str, base_url: str, timeout: float,
                 client: httpx.Client | None = None) -> None:
        self.model, self._key, self.base_url, self.timeout = model, key, base_url, timeout
        self._client = client

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        try:
            if self._client is not None:
                r = self._client.post(url, headers=headers, json=body, timeout=self.timeout)
            else:
                r = httpx.post(url, headers=headers, json=body, timeout=self.timeout)
        except httpx.HTTPError as e:
            raise LLMError(f"{self.name} request failed: {type(e).__name__}") from None
        if r.status_code >= 400:
            raise LLMError(f"{self.name} returned HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError:
            raise LLMError(f"{self.name} returned a non-JSON response") from None

    def generate_json(self, system: str, user: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class Gemini(Provider):
    name = "gemini"

    def generate_json(self, system: str, user: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        data = self._post(url, {"x-goog-api-key": self._key}, {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2}})
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("gemini response had no text candidate") from None


class OpenAICompatible(Provider):
    """OpenAI, Ollama, LM Studio, vLLM ... anything that serves /chat/completions."""
    name = "openai_compatible"

    def generate_json(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        data = self._post(f"{self.base_url.rstrip('/')}/chat/completions", headers, {
            "model": self.model, "temperature": 0.2, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("chat completion response had no content") from None


class Anthropic(Provider):
    name = "anthropic"

    def generate_json(self, system: str, user: str) -> str:
        data = self._post("https://api.anthropic.com/v1/messages",
                          {"x-api-key": self._key, "anthropic-version": "2023-06-01"},
                          {"model": self.model, "max_tokens": 2000, "temperature": 0.2, "system": system,
                           "messages": [{"role": "user", "content": user}]})
        try:
            return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError):
            raise LLMError("anthropic response had no text content") from None


def get_provider(settings: Settings | None = None, client: httpx.Client | None = None) -> Provider:
    """Build the configured provider or raise LLMNotConfigured with an actionable message."""
    s = settings or get_settings()
    name = (s.llm_provider or "none").lower()
    if name in ("", "none"):
        raise LLMNotConfigured("LLM_PROVIDER is 'none'; set LLM_PROVIDER to gemini, openai, anthropic, "
                               "ollama or openai_compatible to enable LLM analysis")
    if name not in DEFAULT_MODELS:
        raise LLMNotConfigured(f"Unknown LLM_PROVIDER '{name}'")
    key = s.llm_key()
    if name in NEEDS_KEY and not key:
        raise LLMNotConfigured(f"LLM_PROVIDER={name} requires LLM_API_KEY (or {name.upper()}_API_KEY)")
    base = s.llm_base_url or DEFAULT_BASE.get(name, "")
    if name in ("openai_compatible",) and not base:
        raise LLMNotConfigured("LLM_PROVIDER=openai_compatible requires LLM_BASE_URL")
    model = s.llm_model or DEFAULT_MODELS[name]
    cls = {"gemini": Gemini, "anthropic": Anthropic}.get(name, OpenAICompatible)
    return cls(model, key, base, s.llm_timeout_seconds, client)


def status(settings: Settings | None = None) -> dict:
    """Configuration status for the UI; never includes the key."""
    s = settings or get_settings()
    try:
        p = get_provider(s)
        return {"configured": True, "provider": s.llm_provider, "model": p.model}
    except LLMNotConfigured as e:
        return {"configured": False, "provider": s.llm_provider, "reason": str(e)}
