
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL, LLM_BACKEND

log = logging.getLogger("llm-backend")


class LLMBackend(ABC):
    @abstractmethod
    def complete(self, prompt: str, system: str | None, max_tokens: int) -> str:
        ...


class MockLLMBackend(LLMBackend):
    """Deterministic, canned responses -- enough to exercise the full
    request -> scan -> "call the model" -> scan -> response pipeline
    without needing any credentials."""

    def complete(self, prompt: str, system: str | None, max_tokens: int) -> str:
        return (
            "This is a mock LLM response (LLM_BACKEND=mock). "
            f"It received a prompt of {len(prompt)} characters. "
            "Set LLM_BACKEND=anthropic and ANTHROPIC_API_KEY to call a real model."
        )


class AnthropicBackend(LLMBackend):
    def __init__(self) -> None:
        import anthropic  # imported lazily so `mock` mode never needs the package installed

        if not ANTHROPIC_API_KEY:
            raise RuntimeError("LLM_BACKEND=anthropic requires ANTHROPIC_API_KEY to be set")
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    def complete(self, prompt: str, system: str | None, max_tokens: int) -> str:
        kwargs = {"model": ANTHROPIC_MODEL, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]}
        if system:
            kwargs["system"] = system
        response = self._client.messages.create(**kwargs)
        return "".join(block.text for block in response.content if block.type == "text")


def build_llm_backend() -> LLMBackend:
    if LLM_BACKEND == "anthropic":
        log.info("Using Anthropic backend, model=%s", ANTHROPIC_MODEL)
        return AnthropicBackend()

    log.info("Using MOCK LLM backend (set LLM_BACKEND=anthropic + ANTHROPIC_API_KEY for a real model)")
    return MockLLMBackend()
