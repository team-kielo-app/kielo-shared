"""Seam — high-level translation entry point per ADR-007.

Mirrors the Go `kielo-shared/localization.Seam` so Python services
(engine, ingest, processor, communications, content) and Go services
(mobile-bff, user-service, convo-orchestrator, content-service) share
identical resolution semantics.

The Seam sits above the existing decorator stack (cache + metrics +
fallback + routing + provider). Callers no longer plug into the
decorator chain directly — they hand the Seam a SourceRef and a target
locale and get back a string. The Seam handles:

  * English passthrough (target=en or target empty → return SourceText)
  * Admin-override lookup (localization.translations rows with
    status='approved'|'override' win over machine translations)
  * Source-version-pinned cache keys (author edit bumps version,
    making stale translations unreachable instead of leaking)
  * Single-flight on cache miss (one in-flight provider call per key
    even when many requests pile on simultaneously)
  * Stale-while-revalidate (returns the cached value past freshTTL +
    kicks off a background refresh; only returns "miss" past total TTL)
  * Telemetry on every call labeled by namespace, target_locale, and
    the resolution path that served the value

Telemetry source labels (stable, dashboarded):

  * "english_passthrough" — target empty / "en" / source text empty
  * "override"            — served from OverrideStore.lookup
  * "cache_hit"           — fresh cache hit
  * "cache_swr"           — stale cache hit, background refresh kicked off
  * "cache_miss_share"    — single-flight share of an in-flight provider call
  * "provider_call"       — provider invoked, value cached
  * "provider_error"      — provider unavailable / errored / returned empty
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
from typing import Iterable, Protocol

from kielo_shared.localization.budget import (
    BudgetKind as _BudgetKind,
    record_budget as _record_budget,
)
from kielo_shared.localization.registry import LocalizationRegistry
from kielo_shared.localization.routing import TIER_A_LOCALE
from kielo_shared.localization.types import (
    TranslationItem,
    TranslationResult,
    TranslationRole,
)

logger = logging.getLogger(__name__)


# ──────────────────────── SourceRef ──────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class SourceRef:
    """Identifies a unique translatable string by namespace + source id +
    source version. Two refs with identical (namespace, source_id,
    source_version) refer to the same canonical English text — the seam
    serves the same cached translation for both.

    source_version is the cache-busting key. When an author edits the
    canonical English source, callers must bump source_version
    (typically by hashing source_text + updated_at) so stale
    translations from before the edit become unreachable. Use
    source_version_from_text() to compute consistently across services.
    """

    namespace: str
    source_id: str
    source_version: str
    source_text: str
    role: TranslationRole = "plain"


def source_version_from_text(*parts: str) -> str:
    """Derive a stable 16-hex-char cache-key suffix from the source text
    (and any other inputs the caller wants to bust on). Callers that
    want updated_at-based busting should pass `(text, updated_at_iso)`.

    Identical inputs yield identical output. Different inputs yield
    different output (sha256-strong). Truncated to 8 bytes / 16 hex
    chars — plenty of collision-resistance within a namespace and
    small enough to keep cache keys readable.
    """
    h = hashlib.sha256()
    for i, part in enumerate(parts):
        if i > 0:
            h.update(b"|")
        h.update(part.encode("utf-8"))
    return h.hexdigest()[:16]


# ──────────────────────── Dependency protocols ───────────────────────────


class Cache(Protocol):
    """Translation cache abstraction. Implementations live service-side
    (Redis-backed) so this package doesn't pull in aioredis."""

    async def get(self, key: str) -> tuple[str | None, float | None]:
        """Return (value, age_seconds). When no entry exists, return
        (None, None)."""

    async def set(self, key: str, value: str, ttl_seconds: float) -> None: ...


class OverrideStore(Protocol):
    """Reads admin-approved translations from localization.translations.

    The seam consults overrides BEFORE the cache so admin-curated
    strings always win over machine translations — even fresh cache
    entries get bypassed.

    Filter on status AND source_version server-side: only status in
    ('approved', 'override') AND source_version = requested version
    should be returned. Stale-source-version rows must NOT surface —
    they were reviewed against different English text. Implementations
    should flip stale rows to 'pending_review' out-of-band so admin-ui
    catches them in the audit queue.
    """

    async def lookup(
        self,
        namespace: str,
        source_id: str,
        source_version: str,
        target_locale: str,
    ) -> str | None: ...


class Metrics(Protocol):
    """One Record call per Seam.translate invocation, labeled by
    (namespace, target_locale, source). See module docstring for the
    canonical source values."""

    def record(self, namespace: str, target_locale: str, source: str) -> None: ...


# ──────────────────────── Noop/test implementations ──────────────────────


class NoopCache:
    """Cache that never hits. Use in environments without Redis. The
    seam still works — every translation just goes to the provider."""

    async def get(self, key: str) -> tuple[str | None, float | None]:
        return None, None

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        return None


class NoopOverrideStore:
    """OverrideStore that always returns 'not found'."""

    async def lookup(
        self,
        namespace: str,
        source_id: str,
        source_version: str,
        target_locale: str,
    ) -> str | None:
        return None


class MapOverrideStore:
    """Deterministic in-memory OverrideStore for unit tests. Keys are
    'namespace|source_id|source_version|target_locale'. Use '*' as
    source_version to match any version in tests that don't exercise
    version semantics."""

    def __init__(self, entries: dict[str, str] | None = None) -> None:
        self._entries = dict(entries or {})

    async def lookup(
        self,
        namespace: str,
        source_id: str,
        source_version: str,
        target_locale: str,
    ) -> str | None:
        exact = self._entries.get(
            f"{namespace}|{source_id}|{source_version}|{target_locale}"
        )
        if exact is not None:
            return exact
        return self._entries.get(f"{namespace}|{source_id}|*|{target_locale}")

    def set(
        self,
        namespace: str,
        source_id: str,
        source_version: str,
        target_locale: str,
        value: str,
    ) -> None:
        self._entries[f"{namespace}|{source_id}|{source_version}|{target_locale}"] = (
            value
        )


class NoopMetrics:
    def record(self, namespace: str, target_locale: str, source: str) -> None:
        return None


class CountingMetrics:
    """In-memory Metrics for tests. Lets tests assert the resolution
    path taken for a given input without standing up Prometheus."""

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], int] = {}

    def record(self, namespace: str, target_locale: str, source: str) -> None:
        key = (namespace, target_locale, source)
        self._counts[key] = self._counts.get(key, 0) + 1

    def count(self, namespace: str, target_locale: str, source: str) -> int:
        return self._counts.get((namespace, target_locale, source), 0)

    def total(self) -> int:
        return sum(self._counts.values())


# ──────────────────────── Seam ───────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class SeamConfig:
    """Seam knobs. Defaults match production expectations for content."""

    fresh_ttl_seconds: float = 24 * 60 * 60
    stale_ttl_seconds: float = 6 * 24 * 60 * 60


class Seam:
    """High-level translation entry point per ADR-007.

    Wire dependencies once at service startup and call ``translate`` /
    ``translate_batch`` per request. The Seam never raises on provider
    errors — it falls back to source text so the UI always has
    something to render.
    """

    def __init__(
        self,
        registry: LocalizationRegistry,
        *,
        cache: Cache | None = None,
        overrides: OverrideStore | None = None,
        metrics: Metrics | None = None,
        config: SeamConfig | None = None,
    ) -> None:
        self._registry = registry
        self._cache = cache or NoopCache()
        self._overrides = overrides or NoopOverrideStore()
        self._metrics = metrics or NoopMetrics()
        self._config = config or SeamConfig()
        self._inflight: dict[str, asyncio.Future[str]] = {}
        self._swr_inflight: set[str] = set()
        self._lock = asyncio.Lock()

    async def translate(self, ref: SourceRef, target_locale: str) -> str:
        """Resolve ref to a localized string. Never returns empty for a
        non-empty source_text — every error path falls back to source."""
        # Sweep YYYY: record 1 ref per single-item resolve (sibling of
        # Go seam's RecordBudget on Translate).
        _record_budget(_BudgetKind.REF_RESOLVED, 1)
        source, value = await self._resolve(ref, target_locale)
        self._metrics.record(ref.namespace, target_locale, source)
        return value

    async def translate_batch(
        self,
        refs: Iterable[SourceRef],
        target_locale: str,
    ) -> list[str]:
        """Resolve many refs to the same target locale. Each item is
        resolved independently; single-flight coalesces duplicates.

        Sweep YYYY note: REF_RESOLVED is recorded by the per-item
        ``translate`` calls inside the gather (1 per ref → N total).
        We don't double-count at the batch entry. When the Python
        seam grows a true batch path (sibling of Go TTTT-B), this
        method will switch to a single composite override lookup +
        Redis MGET + provider batch, and the per-phase counters
        will reflect the new shape (1 override / 1 cache get / 1
        provider call, regardless of N).
        """
        refs_list = list(refs)
        return await asyncio.gather(
            *(self.translate(r, target_locale) for r in refs_list)
        )

    # ──────────────────── resolution chain ───────────────────────────

    async def _resolve(self, ref: SourceRef, target_locale: str) -> tuple[str, str]:
        if not ref.source_text or not ref.source_text.strip():
            return "english_passthrough", ""

        # Coerce to str defensively: FastAPI Query objects, IntEnums and
        # other duck-typed values reach the seam from direct test calls.
        # Forcing str() keeps the seam tolerant of caller weirdness; if
        # the value can't be stringified meaningfully the lower() result
        # is empty and we fall through to english_passthrough.
        target_str = str(target_locale) if target_locale is not None else ""
        target = target_str.strip().lower() if target_str else ""
        if not target or target == TIER_A_LOCALE:
            return "english_passthrough", ref.source_text

        # Sweep YYYY: per-phase counters. Sibling of the Go seam's
        # RecordBudget calls in seam.go::Translate. Override lookup
        # always runs (the override store hit/miss is what the counter
        # measures — the lookup itself counts regardless of outcome).
        _record_budget(_BudgetKind.OVERRIDE_LOOKUP, 1)
        override = await self._overrides.lookup(
            ref.namespace,
            ref.source_id,
            ref.source_version,
            target,
        )
        if override:
            return "override", override

        cache_key = self._cache_key(ref, target)
        _record_budget(_BudgetKind.CACHE_GET, 1)
        cached_value, cached_age = await self._cache.get(cache_key)
        if cached_value is not None and cached_age is not None:
            if cached_age <= self._config.fresh_ttl_seconds:
                return "cache_hit", cached_value
            if (
                cached_age
                <= self._config.fresh_ttl_seconds + self._config.stale_ttl_seconds
            ):
                self._kickoff_swr(ref, target, cache_key)
                return "cache_swr", cached_value

        return await self._provider_path(ref, target, cache_key)

    async def _provider_path(
        self,
        ref: SourceRef,
        target: str,
        cache_key: str,
    ) -> tuple[str, str]:
        # Single-flight: if another coroutine is already resolving this
        # key, await its future instead of issuing a duplicate provider
        # call. The lock is held only long enough to swap or read the
        # in-flight slot.
        async with self._lock:
            existing = self._inflight.get(cache_key)
            if existing is not None:
                future = existing
                shared = True
            else:
                future = asyncio.get_event_loop().create_future()
                self._inflight[cache_key] = future
                shared = False

        if shared:
            value = await future
            return "cache_miss_share", value

        try:
            value = await self._call_provider(ref, target, cache_key)
        except Exception:
            logger.exception(
                "seam provider call failed",
                extra={
                    "namespace": ref.namespace,
                    "source_id": ref.source_id,
                    "target": target,
                },
            )
            value = ref.source_text
            # Distinguish provider_error from provider_call in metrics —
            # caller's metrics.record happens in translate(), so we
            # signal via the source tag.
            future.set_result(value)
            async with self._lock:
                self._inflight.pop(cache_key, None)
            return "provider_error", value

        future.set_result(value)
        async with self._lock:
            self._inflight.pop(cache_key, None)
        return "provider_call", value

    async def _call_provider(self, ref: SourceRef, target: str, cache_key: str) -> str:
        # Sweep YYYY: count each unique provider dispatch. Sibling of
        # Go seam's RecordBudget(PROVIDER_CALL) in the provider-path.
        # Single-flight coalescing in _provider_path means we only land
        # here for cache-misses that aren't already in flight, so this
        # counts unique LLM/opus-mt round-trips.
        _record_budget(_BudgetKind.PROVIDER_CALL, 1)
        provider = self._registry.resolve(
            source_locale=TIER_A_LOCALE, target_locale=target
        )
        items = [
            TranslationItem(
                text=ref.source_text,
                role=ref.role,
                cache_key=cache_key,
            )
        ]
        results: list[TranslationResult] = await provider.translate_batch(
            items,
            source_locale=TIER_A_LOCALE,
            target_locale=target,
        )
        if not results:
            return ref.source_text
        value = (results[0].text or "").strip()
        if not value:
            return ref.source_text
        await self._cache.set(
            cache_key,
            value,
            self._config.fresh_ttl_seconds + self._config.stale_ttl_seconds,
        )
        return value

    def _kickoff_swr(self, ref: SourceRef, target: str, cache_key: str) -> None:
        if cache_key in self._swr_inflight:
            return
        self._swr_inflight.add(cache_key)

        async def refresh() -> None:
            try:
                await self._call_provider(ref, target, cache_key)
            except Exception:
                logger.exception(
                    "seam SWR refresh failed",
                    extra={
                        "namespace": ref.namespace,
                        "source_id": ref.source_id,
                        "target": target,
                    },
                )
            finally:
                self._swr_inflight.discard(cache_key)

        try:
            asyncio.get_event_loop().create_task(refresh())
        except RuntimeError:
            # No running loop — synchronous caller or shutdown. Drop
            # the refresh silently; the next request still gets stale
            # data within staleTTL.
            self._swr_inflight.discard(cache_key)

    @staticmethod
    def _cache_key(ref: SourceRef, target: str) -> str:
        return (
            f"kielo:i18n:{ref.namespace}:{ref.source_id}:{ref.source_version}:{target}"
        )
