"""LLMRegistry — task → provider routing.

Registry lookup keys on `task` (free-form caller tag) instead of locale
pair like the localization registry. Routing precedence:

  1. Exact task → provider id (e.g. `LLM_ROUTE_grammar_example=openai_eval`)
  2. Default provider id (`LLM_PROVIDER_DEFAULT`)

Failing to register a routed provider id raises `UnknownLLMProviderError`
— fail-loud over silent fallback.
"""

from __future__ import annotations

import os
from threading import Lock

from kielo_shared.llm.provider import LLMProvider


class UnknownLLMProviderError(LookupError):
    """Resolved provider id is not registered."""


class LLMRegistry:
    """In-process registry of `provider_id → LLMProvider` and `task → provider_id`."""

    def __init__(self, *, default_provider_id: str | None = None) -> None:
        self._providers: dict[str, LLMProvider] = {}
        self._task_routes: dict[str, str] = {}
        self.default_provider_id: str | None = default_provider_id

    # ─────────────────────────── registration ────────────────────────────

    def register(self, provider_id: str, provider: LLMProvider) -> None:
        if not provider_id:
            raise ValueError("provider_id is required")
        self._providers[provider_id] = provider

    def route(self, task: str, provider_id: str) -> None:
        if not provider_id:
            raise ValueError("provider_id is required")
        self._task_routes[task] = provider_id

    def set_default(self, provider_id: str) -> None:
        self.default_provider_id = provider_id

    # ───────────────────────────── resolution ────────────────────────────

    def resolve(self, *, task: str = "generic") -> LLMProvider:
        provider_id = self._task_routes.get(task) or self.default_provider_id
        if provider_id is None:
            raise UnknownLLMProviderError(
                f"No route for task={task!r} and no default provider. "
                "Set LLM_PROVIDER_DEFAULT or call registry.set_default()."
            )
        provider = self._providers.get(provider_id)
        if provider is None:
            raise UnknownLLMProviderError(
                f"No provider registered for id={provider_id!r} "
                f"(task={task!r}). Register it before resolving."
            )
        return provider

    # ─────────────────────── introspection (tests) ───────────────────────

    @property
    def registered_ids(self) -> tuple[str, ...]:
        return tuple(self._providers.keys())

    @property
    def task_routes(self) -> dict[str, str]:
        return dict(self._task_routes)


# ───────────────────────────── env loader ────────────────────────────────


def build_llm_registry_from_env(env: dict[str, str] | None = None) -> LLMRegistry:
    """Build a registry from `LLM_*` env vars.

    Concrete provider instances are NOT registered here — call sites do
    that after construction so this layer stays SDK-free.
    """
    e = env if env is not None else dict(os.environ)
    registry = LLMRegistry(
        default_provider_id=e.get("LLM_PROVIDER_DEFAULT") or None,
    )
    for key, value in e.items():
        if not key.startswith("LLM_ROUTE_"):
            continue
        task = key[len("LLM_ROUTE_") :].lower()
        if task and value:
            registry.route(task, value)
    return registry


# ─────────────────────── default-instance singleton ──────────────────────


_default_registry: LLMRegistry | None = None
_default_registry_lock = Lock()


def get_default_llm_registry() -> LLMRegistry:
    global _default_registry
    if _default_registry is None:
        with _default_registry_lock:
            if _default_registry is None:
                _default_registry = build_llm_registry_from_env()
    return _default_registry


def reset_default_llm_registry() -> None:
    global _default_registry
    with _default_registry_lock:
        _default_registry = None


__all__ = [
    "LLMRegistry",
    "UnknownLLMProviderError",
    "build_llm_registry_from_env",
    "get_default_llm_registry",
    "reset_default_llm_registry",
]
