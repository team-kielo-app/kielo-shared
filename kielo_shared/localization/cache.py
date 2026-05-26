"""RedisCacheDecorator — Phase C1.

Wraps a `LocalizationProvider` with a Redis-backed read-through cache.

Cache key scheme:
    loc:{provider_id}:{source}:{target}:{role}:{sha256(text)[:32]}

Including `provider_id` in the key keeps caches scoped per provider so a
provider swap doesn't poison the namespace — old entries simply never get
read again. Including `role` keeps html / gloss / plain bins distinct (a
gloss translation is shorter and stricter than the plain version of the
same text).

Behavior:
  * Per-item read: GET → if hit, mark cached=True, latency≈0, skip inner.
  * Misses are collected, sent through inner.translate_batch in ONE call,
    then results are written back with TTL.
  * Cache write/read failures degrade silently to the inner provider —
    Redis going down does not break translation.

The decorator stores the translated TEXT only, not the full
`TranslationResult`, because provenance fields (`provider_id`, `metadata`,
`correlation_id`) belong to THIS request, not the original cached one.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, Awaitable, Protocol

from kielo_shared.localization.provider import LocalizationProvider
from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# Minimal redis-async surface we depend on. `redis.asyncio.Redis` ships
# this; tests can plug a fake.
class RedisAsyncClient(Protocol):
    async def get(self, key: str) -> Any: ...

    async def set(self, key: str, value: str, ex: int | None = None) -> Any: ...


def _key_for(
    *,
    provider_id: str,
    source_locale: str,
    target_locale: str,
    item: TranslationItem,
) -> str:
    """Deterministic cache key.

    `cache_key` on the item, when supplied, takes precedence so callers can
    force dedup across slightly-different texts (e.g. html-stripped form +
    raw form should share the same cache slot).
    """
    if item.cache_key:
        digest_input = item.cache_key
    else:
        digest_input = item.text or ""
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:32]
    base = (target_locale or "").split("-", 1)[0].lower() or "_"
    src = (source_locale or "").split("-", 1)[0].lower() or "_"
    return f"loc:{provider_id}:{src}:{base}:{item.role}:{digest}"


class RedisCacheDecorator:
    """Read-through cache for translations.

    Args:
      inner: provider being wrapped.
      redis: async client (real or stub).
      ttl_sec: how long entries live. 7 days is reasonable for stable
        learner-facing strings; tighten in env if needed.
      key_prefix: optional namespace override (per-deployment isolation).
    """

    def __init__(
        self,
        inner: LocalizationProvider,
        redis: RedisAsyncClient | None,
        *,
        ttl_sec: int = 7 * 24 * 3600,
        key_prefix: str | None = None,
    ) -> None:
        self._inner = inner
        self._redis = redis
        self._ttl = ttl_sec
        self._prefix = key_prefix

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        if not items or self._redis is None:
            return await self._inner.translate_batch(
                items,
                source_locale=source_locale,
                target_locale=target_locale,
                idempotency_key=idempotency_key,
            )

        keys = [
            self._maybe_prefix(
                _key_for(
                    provider_id=self._inner.provider_id,
                    source_locale=source_locale,
                    target_locale=target_locale,
                    item=item,
                )
            )
            for item in items
        ]

        # 1) Fan-out GETs in parallel — Redis pipelines this server-side.
        cached_texts: list[str | None] = await asyncio.gather(
            *(self._safe_get(k) for k in keys), return_exceptions=False
        )

        results: list[TranslationResult | None] = [None] * len(items)
        miss_indices: list[int] = []
        miss_items: list[TranslationItem] = []

        for i, cached in enumerate(cached_texts):
            if isinstance(cached, str) and cached:
                results[i] = TranslationResult(
                    text=cached,
                    provider=self._inner.provider_id,
                    cached=True,
                    latency_ms=0,
                    correlation_id="",
                    metadata={"role": items[i].role, "cache": "hit"},
                )
            else:
                miss_indices.append(i)
                miss_items.append(items[i])

        # 2) Single batched call for everything that missed.
        if miss_items:
            inner_results = await self._inner.translate_batch(
                miss_items,
                source_locale=source_locale,
                target_locale=target_locale,
                idempotency_key=idempotency_key,
            )
            if len(inner_results) != len(miss_items):
                logger.warning(
                    "RedisCacheDecorator: inner returned %d results for %d misses; "
                    "skipping cache write for safety.",
                    len(inner_results),
                    len(miss_items),
                )
                for slot, r in zip(miss_indices, inner_results, strict=False):
                    results[slot] = r
            else:
                # 3) Write results back. Skip provenance-marked passthroughs —
                # caching a passthrough would lock the source text in place
                # if a real provider becomes available later.
                set_tasks: list[Awaitable[Any]] = []
                for slot, r in zip(miss_indices, inner_results, strict=True):
                    results[slot] = r
                    if r.provider == "passthrough":
                        continue
                    if not (r.text or "").strip():
                        continue
                    set_tasks.append(self._safe_set(keys[slot], r.text))
                if set_tasks:
                    await asyncio.gather(*set_tasks, return_exceptions=False)

        # All slots filled (results contain TranslationResult, never None
        # here because inner is mandated to return one-per-input).
        return [
            r if r is not None else self._passthrough(items[i])
            for i, r in enumerate(results)
        ]

    # ─────────────────────────── helpers ─────────────────────────────────

    def _maybe_prefix(self, key: str) -> str:
        return f"{self._prefix}:{key}" if self._prefix else key

    @staticmethod
    def _passthrough(item: TranslationItem) -> TranslationResult:
        return TranslationResult(text=item.text, provider="passthrough")

    async def _safe_get(self, key: str) -> str | None:
        try:
            value = await self._redis.get(key)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("RedisCacheDecorator GET failed key=%s: %s", key, exc)
            return None
        if value is None:
            return None
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if isinstance(value, str):
            return value
        return None

    async def _safe_set(self, key: str, text: str) -> None:
        try:
            await self._redis.set(key, text, ex=self._ttl)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("RedisCacheDecorator SET failed key=%s: %s", key, exc)


__all__ = ["RedisAsyncClient", "RedisCacheDecorator"]
