"""Provider registry + env-driven routing.

Routing rules, in order of precedence:
  1. Exact route: `(source, target)` match → registered provider id.
  2. Wildcard target: `(source, "*")`.
  3. Wildcard source: `("*", target)`.
  4. Default: registry.default_provider.

A request for a route whose provider id has not been registered raises
`UnknownProviderError` — fail-loud over silently swapping to a default.

Env layout (read by `build_registry_from_env`):

    LOC_PROVIDER_DEFAULT=openai_gpt4o_mini
    LOC_ROUTE_EN_VI=openai_gpt4o_mini
    LOC_ROUTE_EN_*=openai_gpt4o_mini
    LOC_ROUTE_*_*=openai_gpt4o_mini

`LOC_ROUTE_<SOURCE>_<TARGET>` keys add per-pair overrides; `*` is the
wildcard sentinel and must be uppercase to read clean.
"""

from __future__ import annotations

import os
from threading import Lock
from typing import Iterable

from kielo_shared.localization.provider import LocalizationProvider


class UnknownProviderError(LookupError):
    """Raised when a route resolves to a provider id that wasn't registered."""


class LocalizationRegistry:
    """In-process registry of `provider_id → LocalizationProvider`.

    Not thread-safe for concurrent register() / route() — registry is
    expected to be built once at startup and read-only afterwards.
    """

    def __init__(self, *, default_provider_id: str | None = None) -> None:
        self._providers: dict[str, LocalizationProvider] = {}
        self._routes: dict[tuple[str, str], str] = {}
        self.default_provider_id: str | None = default_provider_id

    # ──────────────────────────── registration ───────────────────────────
    def register(self, provider_id: str, provider: LocalizationProvider) -> None:
        if not provider_id:
            raise ValueError("provider_id is required")
        self._providers[provider_id] = provider

    def route(self, source: str, target: str, provider_id: str) -> None:
        """Add (or replace) a route. Use "*" for either slot as wildcard."""
        if not provider_id:
            raise ValueError("provider_id is required")
        self._routes[(source, target)] = provider_id

    def set_default(self, provider_id: str) -> None:
        self.default_provider_id = provider_id

    # ───────────────────────────── resolution ────────────────────────────
    def resolve(
        self, *, source_locale: str, target_locale: str
    ) -> LocalizationProvider:
        provider_id = self._resolve_provider_id(source_locale, target_locale)
        provider = self._providers.get(provider_id)
        if provider is None:
            raise UnknownProviderError(
                f"No provider registered for id={provider_id!r} "
                f"(route={source_locale!r}->{target_locale!r}). "
                "Register it via registry.register() before resolving."
            )
        return provider

    def _resolve_provider_id(self, source: str, target: str) -> str:
        for key in ((source, target), (source, "*"), ("*", target), ("*", "*")):
            if key in self._routes:
                return self._routes[key]
        if self.default_provider_id is None:
            raise UnknownProviderError(
                f"No route for {source!r}->{target!r} and no default provider. "
                "Set LOC_PROVIDER_DEFAULT or call registry.set_default()."
            )
        return self.default_provider_id

    # ───────────────────────── introspection (tests) ─────────────────────
    @property
    def registered_ids(self) -> Iterable[str]:
        return tuple(self._providers.keys())

    @property
    def routes(self) -> dict[tuple[str, str], str]:
        return dict(self._routes)


# ────────────────────────────── env loader ───────────────────────────────


def build_registry_from_env(
    env: dict[str, str] | None = None,
) -> LocalizationRegistry:
    """Build a registry by reading `LOC_*` env vars.

    Does NOT register concrete provider instances — call sites do that
    after construction so the env layer doesn't pull in heavy deps.
    """
    e = env if env is not None else dict(os.environ)
    registry = LocalizationRegistry(
        default_provider_id=e.get("LOC_PROVIDER_DEFAULT") or None,
    )
    for key, value in e.items():
        if not key.startswith("LOC_ROUTE_"):
            continue
        suffix = key[len("LOC_ROUTE_") :]
        # Expected shape: SOURCE_TARGET (e.g. EN_VI, EN_STAR doesn't apply —
        # use literal "*" via underscores: LOC_ROUTE_EN_*=foo isn't legal as
        # a shell var name, so callers use LOC_ROUTE_EN_STAR=foo or set
        # routes programmatically).
        if "_" not in suffix:
            continue
        source, target = suffix.lower().split("_", 1)
        if source == "star":
            source = "*"
        if target == "star":
            target = "*"
        registry.route(source, target, value)
    return registry


# ───────────────────────── default-instance singleton ────────────────────

_default_registry: LocalizationRegistry | None = None
_default_registry_lock = Lock()


def get_default_registry() -> LocalizationRegistry:
    """Lazy-init a process-global registry from env.

    First caller wins — subsequent calls return the same instance. Use
    `reset_default_registry()` between tests.
    """
    global _default_registry
    if _default_registry is None:
        with _default_registry_lock:
            if _default_registry is None:
                _default_registry = build_registry_from_env()
    return _default_registry


def reset_default_registry() -> None:
    """Clear the cached default registry (test-only)."""
    global _default_registry
    with _default_registry_lock:
        _default_registry = None


__all__ = [
    "LocalizationRegistry",
    "UnknownProviderError",
    "build_registry_from_env",
    "get_default_registry",
    "reset_default_registry",
]
