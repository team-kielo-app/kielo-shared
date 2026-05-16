"""Support-locale registry adapter (ADR-008 Python mirror).

Mirrors the Go `kielo-shared/locale/supportregistry` package so Python
services (kielolearn-engine, kielo-ingest-processor, etc.) can resolve
UI support-locale strings through the same three-layer fallback chain:

  1. Runtime override (future: localization.dynamic_translations via
     ADR-007 — not yet wired into MapRegistry; that's the
     DynamicRegistry composition planned for later phases).
  2. Compile-time seed (in-memory dict, populated at module load).
  3. English fallback (universal, ALWAYS resolves to a usable string;
     never returns the source learning-language text like "teonsana"
     to an English UI).

See docs/architecture/adr-008-support-locale-adapter.md for the full
design rationale. The Go and Python APIs are intentionally parallel so
the same key naming convention works on both sides (and future
DynamicRegistry implementations can share the resource_type
``ui.string`` taxonomy in dynamic_translations).

Two-line summary:

  - Every per-locale switch (``if support_locale == 'vi': return X``)
    in Python services is replaced by
    ``registry.resolve(key, support_locale)``.
  - Adding a new locale becomes "add seed entries", not "touch dozens
    of files across the engine".

Usage::

    from kielo_shared.localization.support_registry import MapRegistry

    REGISTRY = MapRegistry(supported_locales=["en", "vi", "fi", "sv"])
    REGISTRY.set("ui.exercise.prompt.fill_in_blank", "en", "Fill in the blank.")
    REGISTRY.set("ui.exercise.prompt.fill_in_blank", "vi", "Điền vào chỗ trống.")
    REGISTRY.finalize()

    # In a handler:
    text = REGISTRY.resolve("ui.exercise.prompt.fill_in_blank", support_locale)
"""
from __future__ import annotations

import logging
import string
import threading
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger(__name__)


# Universal last-resort seed locale. Resolve returns the English seed
# whenever the requested support_locale has no entry for the key.
# English MUST always have a seed for keys whose intermediate locale
# coverage is partial — registries with missing English entries return
# the key string verbatim, which the caller's facade then maps to
# whatever English source it has at hand.
FALLBACK_LOCALE = "en"


@dataclass
class CoverageStats:
    """Per-locale completion stats. Mirrors Go's CoverageStats."""

    total: int = 0       # total registered keys
    localized: int = 0   # keys with a non-English seed for this locale
    overridden: int = 0  # keys with a runtime override (future)
    fallback: int = 0    # keys where this locale falls through to English


class SupportRegistry(Protocol):
    """Protocol for support-locale string resolution.

    Implementations MUST satisfy:

      1. ``resolve`` returns a non-empty string for every support_locale
         in ``supported_locales()``. If the requested key has no
         localization for support_locale, the registry falls through to
         the English seed. If even English is missing, the implementation
         returns the key itself (never empty, never the source
         learning-language text).
      2. ``resolve`` is safe for concurrent calls.
      3. ``resolve_template`` applies str.format-style substitution after
         resolve. Templates that fail to format return the literal
         resolved string (best-effort degrade).

    Async paths (Phase 5 DynamicRegistry):

      4. ``aresolve`` is the async counterpart. For pure in-memory
         implementations (MapRegistry) it just calls ``resolve``. For
         DB-backed implementations (DynamicRegistry) it awaits the
         override probe + falls back to the seed on miss. Callers in
         async contexts should prefer ``aresolve`` over ``resolve``
         when an override-capable registry might be wired.
      5. ``aresolve_template`` is the async counterpart of
         ``resolve_template``. Same template-handling contract.

    The async surface is additive — every SupportRegistry MUST
    implement both sync and async methods. Pure in-memory
    implementations can trivially make ``aresolve`` an ``async def``
    that just returns ``self.resolve(...)``; the small overhead is
    acceptable because in-memory registries are usually wrapped by
    a DynamicRegistry in production paths.
    """

    def resolve(self, key: str, support_locale: str) -> str: ...

    def resolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str: ...

    async def aresolve(self, key: str, support_locale: str) -> str: ...

    async def aresolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str: ...

    def supported_locales(self) -> list[str]: ...

    def coverage_report(self) -> dict[str, CoverageStats]: ...


def _normalize(locale: str) -> str:
    """Normalize a locale code to lowercase, trimmed. BCP-47 region
    stripping (e.g. ``vi-VN`` → ``vi``) is the caller's responsibility
    via ``kielo_shared.locale_constants`` — the registry just does the
    trivial case/space normalization."""
    return locale.strip().lower() if locale else ""


@dataclass
class MapRegistry:
    """In-memory SupportRegistry backed by a static dict.

    Concurrent-safe for reads (Python's dict reads are atomic under
    the GIL; we lock writes for clarity). Seeds are loaded once via
    ``set`` or bulk constructors; callers SHOULD ``finalize`` at module
    load so any further ``set`` calls raise loud.

    Construction::

        r = MapRegistry(supported_locales=["en", "vi", "fi"])
        r.set("ui.greeting", "en", "Hello")
        r.set("ui.greeting", "vi", "Xin chào")
        r.finalize()

    English is always included in supported_locales — if the caller
    omits it, it's appended automatically (matches Go's New() behavior).
    """

    supported_locales_in: list[str] = field(default_factory=list)
    _seeds: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    _supported: list[str] = field(default_factory=list, repr=False)
    _finalized: bool = field(default=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for code in self.supported_locales_in:
            normalized = _normalize(code)
            if normalized and normalized not in seen:
                self._supported.append(normalized)
                seen.add(normalized)
        if FALLBACK_LOCALE not in seen:
            self._supported.append(FALLBACK_LOCALE)

    def set(self, key: str, support_locale: str, text: str) -> bool:
        """Register a localization. MUST be called before finalize().
        Returns False if the registry is finalized (caller bug)."""
        with self._lock:
            if self._finalized:
                return False
            self._seeds.setdefault(key, {})[_normalize(support_locale)] = text
            return True

    def finalize(self) -> None:
        """Mark the registry read-only. Subsequent set() calls return
        False so test reloads or late hot-patches fail loud."""
        with self._lock:
            self._finalized = True

    def resolve(self, key: str, support_locale: str) -> str:
        entries = self._seeds.get(key)
        if entries is None:
            return key
        normalized = _normalize(support_locale)
        if normalized:
            text = entries.get(normalized)
            if text:
                return text
        text = entries.get(FALLBACK_LOCALE)
        if text:
            return text
        return key

    def resolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str:
        """Resolve + ``str.format_map`` substitution.

        Uses Python's ``string.Formatter`` with a default-empty
        fallback so missing placeholders don't raise KeyError. A
        malformed format string returns the literal resolved value
        rather than crashing the caller — same best-effort-degrade
        contract as the Go ResolveTemplate."""
        text = self.resolve(key, support_locale)
        if "{" not in text:
            return text
        try:
            return _SafeFormatter().vformat(text, (), params)
        except (KeyError, IndexError, ValueError) as exc:
            logger.warning(
                "support_registry template parse failed for key=%s locale=%s: %s",
                key, support_locale, exc,
            )
            return text

    async def aresolve(self, key: str, support_locale: str) -> str:
        """Async counterpart of ``resolve``. For MapRegistry this is a
        thin shim that just calls the sync path — there's nothing to
        await on a pure in-memory dict lookup.

        Exists so MapRegistry satisfies the SupportRegistry Protocol's
        full surface, which DynamicRegistry uses as its contract. Any
        async caller that holds a generic ``SupportRegistry`` reference
        can await ``aresolve`` regardless of whether the concrete
        instance is MapRegistry or DynamicRegistry."""
        return self.resolve(key, support_locale)

    async def aresolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str:
        """Async counterpart of ``resolve_template``. Same rationale
        as ``aresolve`` — thin shim over the sync path."""
        return self.resolve_template(key, support_locale, **params)

    def supported_locales(self) -> list[str]:
        return list(self._supported)

    def coverage_report(self) -> dict[str, CoverageStats]:
        report: dict[str, CoverageStats] = {}
        for locale in self._supported:
            stats = CoverageStats()
            for entries in self._seeds.values():
                stats.total += 1
                if locale in entries:
                    stats.localized += 1
                elif FALLBACK_LOCALE in entries:
                    stats.fallback += 1
            report[locale] = stats
        return report


class _SafeFormatter(string.Formatter):
    """Formatter that treats missing field names as empty string rather
    than raising KeyError. Mirrors Go text/template's missingkey=zero
    option in spirit, though Python's str.format syntax is different."""

    def get_value(self, key, args, kwargs):
        try:
            return super().get_value(key, args, kwargs)
        except (KeyError, IndexError):
            return ""


def materialize_by_locale(registry: SupportRegistry, key: str) -> dict[str, str]:
    """Snapshot all supported-locale resolutions for one key.

    Mirrors Go's ``MaterializeByLocale``. Useful when a downstream API
    accepts a ``dict[locale, str]`` shape and can't be migrated to
    per-call ``resolve`` without rippling into its tests.

    Locales without a seed for the key fall back to the English seed.
    If even English is missing, that locale is omitted from the result
    rather than emitting the raw key as text.
    """
    out: dict[str, str] = {}
    for locale in registry.supported_locales():
        text = registry.resolve(key, locale)
        if text == key:
            continue
        out[locale] = text
    return out
