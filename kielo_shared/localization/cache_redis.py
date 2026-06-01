"""Sweep AAAAA: Redis-backed Cache + BatchCache implementation.

Mirror of Go's ``kielo-shared/localization/cacheredis``. Provides a
seam-layer cache (consumed by ``Seam`` via the Cache / BatchCache
protocols at ``seam.py``). DISTINCT from ``cache.py:RedisCacheDecorator``
which sits one layer deeper inside the provider chain.

Architecture (post-AAAAA):

    Seam.translate_batch
       │
       ├─ Phase 1: BatchOverrideStore.batch_lookup  (PgxBatchOverrideStore)
       │
       ├─ Phase 2: BatchCache.batch_get             ← THIS FILE
       │             └─ 1 Redis MGET + 1 pipelined PTTL
       │
       └─ Phase 3: LocalizationProvider.translate_batch
                       └─ RedisCacheDecorator (per-item GET/SET inside chain)
                              └─ Gemini / OpenAI batch call

The seam cache fronts the provider chain — its hits never reach the
decorator. Different key shape: seam uses
``kielo:i18n:{namespace}:{source_id}:{source_version}:{target}``
(see ``Seam._cache_key``), decorator uses
``loc:{provider_id}:{src}:{tgt}:{role}:{sha256[:32]}``.

Both layers exist because they answer different questions:

- Seam-layer cache: "have we resolved THIS exact source_version of
  THIS resource for THIS target?" — survives provider swaps.
- Provider-layer cache: "have we ever asked THIS provider to
  translate THIS text?" — survives source_version bumps when the
  text content didn't change.

Degrades gracefully on Redis errors: the seam's NoopCache fallback
path applies if this raises (errors are caught + logged, not
propagated). Translation never fails because of Redis.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Protocol

from kielo_shared.localization.seam import CacheEntry


logger = logging.getLogger(__name__)


class RedisPipeline(Protocol):
    """Minimal pipeline surface — redis.asyncio.client.Pipeline ships
    this. Tests can plug a fake."""

    def get(self, key: str) -> "RedisPipeline": ...

    def set(self, key: str, value: str, ex: int | None = None) -> "RedisPipeline": ...

    def pttl(self, key: str) -> "RedisPipeline": ...

    async def execute(self) -> list[Any]: ...


class RedisAsyncClient(Protocol):
    """Minimal subset of ``redis.asyncio.Redis`` we depend on. The
    canonical impl is ``redis.asyncio.Redis(decode_responses=True)``;
    tests can plug a fake-backed dict."""

    async def get(self, key: str) -> Any: ...

    async def set(self, key: str, value: str, ex: int | None = None) -> Any: ...

    async def mget(self, keys: list[str]) -> list[Any]: ...

    async def pttl(self, key: str) -> Any: ...

    def pipeline(self, transaction: bool = False) -> RedisPipeline: ...


class RedisCache:
    """Seam-layer Cache + BatchCache implementation backed by Redis.

    Constructor:
      client: a ``redis.asyncio.Redis`` (or RedisAsyncClient-compatible)
        instance. Typically the same client other parts of the engine
        share via ``redis_service.redis_client``.
      total_ttl_seconds: the TTL used by ``set()`` calls and the basis
        for age computation in ``get()``. Pre-AAAAA the seam computed
        age as (fresh_ttl + stale_ttl) - PTTL/1000 so a freshly-written
        entry has age=0 and ages monotonically as PTTL counts down.

    Implements both the ``Cache`` protocol (per-key get/set, used as
    fallback when the seam runtime-check for BatchCache returns
    False — but since this class IS a BatchCache, the seam's fast
    path always wins) AND the ``BatchCache`` protocol (1 MGET + 1
    pipelined PTTL for batch_get; pipelined SET for batch_set).
    """

    def __init__(
        self,
        client: RedisAsyncClient,
        *,
        total_ttl_seconds: float,
    ) -> None:
        self._client = client
        self._total_ttl_seconds = total_ttl_seconds

    # ─── Cache protocol (single-key — kept for back-compat) ────────────

    async def get(self, key: str) -> tuple[str | None, float | None]:
        try:
            value = await self._client.get(key)
        except Exception:
            logger.exception("RedisCache.get failed for %s", key)
            return None, None
        if value is None:
            return None, None
        try:
            pttl_ms = await self._client.pttl(key)
        except Exception:
            logger.exception("RedisCache.pttl failed for %s", key)
            # We have a value but can't compute age — return age=0 to
            # be conservative (treats it as fresh, matching Go's
            # cacheredis behaviour on PTTL errors).
            return self._coerce_str(value), 0.0
        age = self._age_from_pttl(pttl_ms)
        return self._coerce_str(value), age

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        try:
            ex = int(ttl_seconds) if ttl_seconds > 0 else None
            await self._client.set(key, value, ex=ex)
        except Exception:
            logger.exception("RedisCache.set failed for %s", key)

    # ─── BatchCache protocol (the AAAAA fast path) ─────────────────────

    async def batch_get(self, keys: list[str]) -> dict[str, CacheEntry]:
        """1 MGET round-trip + 1 pipelined PTTL for each hit.

        Returns ``{key: CacheEntry(value, age_seconds)}`` for every
        present key. Misses are simply omitted — callers should check
        ``key in result`` rather than expecting None values.

        Mirror of Go ``cacheredis.Cache.BatchGet`` at
        ``kielo-shared/localization/cacheredis/cache.go:106-163``.
        """
        if not keys:
            return {}

        try:
            values = await self._client.mget(keys)
        except Exception:
            logger.exception("RedisCache.batch_get MGET failed")
            return {}

        # Collect hit keys for the PTTL pipeline. Misses skipped.
        hit_keys: list[str] = []
        hit_values: list[str] = []
        for key, raw in zip(keys, values):
            if raw is None:
                continue
            value = self._coerce_str(raw)
            if value is None:
                continue
            hit_keys.append(key)
            hit_values.append(value)

        if not hit_keys:
            return {}

        # 1 pipelined PTTL per hit — single Exec round-trip.
        ages: list[float] = []
        try:
            pipe = self._client.pipeline(transaction=False)
            for key in hit_keys:
                pipe.pttl(key)
            results = await pipe.execute()
        except Exception:
            logger.exception("RedisCache.batch_get PTTL pipeline failed")
            # Degrade: emit age=0 for every hit (treat as fresh — same
            # as Go cacheredis cache.go fallback).
            return {
                k: CacheEntry(value=v, age_seconds=0.0)
                for k, v in zip(hit_keys, hit_values)
            }

        for raw in results:
            ages.append(self._age_from_pttl(raw))

        return {
            k: CacheEntry(value=v, age_seconds=a)
            for k, v, a in zip(hit_keys, hit_values, ages)
        }

    async def batch_set(self, entries: dict[str, str], ttl_seconds: float) -> None:
        """Pipelined SET per entry, 1 Exec round-trip.

        Mirror of Go ``cacheredis.Cache.BatchSet`` at
        ``kielo-shared/localization/cacheredis/cache.go:168-181``.
        """
        if not entries:
            return
        ex = int(ttl_seconds) if ttl_seconds > 0 else None
        try:
            pipe = self._client.pipeline(transaction=False)
            for key, value in entries.items():
                pipe.set(key, value, ex=ex)
            await pipe.execute()
        except Exception:
            logger.exception("RedisCache.batch_set failed for %d entries", len(entries))

    # ─── helpers ───────────────────────────────────────────────────────

    def _age_from_pttl(self, pttl_ms: Any) -> float:
        """Convert Redis PTTL (ms) to seam age (seconds). PTTL semantics:

          -2 → key does not exist        → age = total TTL (treat as expired)
          -1 → key has no expiry         → age = 0 (treat as fresh)
          >=0 → remaining TTL in ms      → age = total - pttl/1000

        Returns max(0.0, ...) — never negative.
        """
        try:
            pttl_int = int(pttl_ms) if pttl_ms is not None else -2
        except (TypeError, ValueError):
            return self._total_ttl_seconds
        if pttl_int == -2:
            return self._total_ttl_seconds  # expired / missing
        if pttl_int == -1:
            return 0.0  # no expiry — treat as fresh
        age = self._total_ttl_seconds - (pttl_int / 1000.0)
        return max(0.0, age)

    @staticmethod
    def _coerce_str(value: Any) -> str | None:
        """Redis returns ``str`` when decode_responses=True, ``bytes``
        otherwise. Coerce to str; return None for unconvertible."""
        if value is None:
            return None
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except Exception:
                return None
        return str(value)
