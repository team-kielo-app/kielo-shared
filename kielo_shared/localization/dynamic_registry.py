"""Async DynamicRegistry — runtime override layer over a static seed.

Python mirror of ``kielo-shared/locale/supportregistry/dynamicregistry``
(Go). Composes a sync seed ``SupportRegistry`` (typically a finalized
``MapRegistry``) with a runtime-override layer backed by
``localization.dynamic_translations``.

Design (locked in adr-008-support-locale-adapter.md §"Phase 5"):

* ``resource_type = "ui_string"`` — same constant as the Go side.
* ``resource_id = key`` verbatim.
* ``source_version = sha256(english_seed)[:16]`` — lazily computed +
  memoized on first probe per key.
* Probe order: English locale or missing-from-seed → seed (shortcuts,
  no DB probe); cache; DB; seed fallback.
* TTLs: 5 min positive, 30 sec negative.
* Degrade-to-seed on every error path.

Async vs sync surface:

The sync ``resolve`` / ``resolve_template`` methods delegate directly
to the seed and ignore the override layer entirely. This preserves
the sync Protocol contract for in-memory callers and tests; async
callers that want overrides must use ``aresolve`` / ``aresolve_template``.

This is the deliberate design — the sync path is for places that
cannot await (module-load-time string resolution, tests). Anywhere
overrides need to apply, the call site must already be in an async
context (FastAPI request handlers, background workers, etc.).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Awaitable, Callable, Optional, Protocol

from kielo_shared.localization.support_registry import (
    CoverageStats,
    FALLBACK_LOCALE,
    SupportRegistry,
    _SafeFormatter,
    _normalize,
)
from kielo_shared.resource_types import UI_STRING


logger = logging.getLogger(__name__)


# Default TTLs (match the Go constants).
DEFAULT_HIT_TTL_SECONDS = 5 * 60     # 5 minutes
DEFAULT_MISS_TTL_SECONDS = 30        # 30 seconds


# Sentinel for cached-negative entries. Mirrors the Go side. A string
# starting with NUL byte can never be a legitimate translated_text.
_NEGATIVE_SENTINEL = "\x00neg"


class AsyncCache(Protocol):
    """Minimal async cache contract DynamicRegistry needs. Implement
    against aioredis (see ``AsyncRedisCache`` below) or supply
    ``NoopAsyncCache`` for tests / strict-consistency mode."""

    async def get(
        self, key: str
    ) -> tuple[Optional[str], bool, bool]:
        """Return ``(value, is_override, cached_ok)``.

        * ``cached_ok=False``: cache miss; caller probes DB.
        * ``cached_ok=True, is_override=True``: positive cache hit;
          ``value`` is the override string.
        * ``cached_ok=True, is_override=False``: cached-negative;
          definitively no override exists.
        """
        ...

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        """Cache a positive override hit."""
        ...

    async def set_negative(self, key: str, ttl_seconds: int) -> None:
        """Cache 'no override exists' for ``ttl_seconds``."""
        ...


# Probe function type — same signature as the Go dbProbeFunc but async.
# Returns (value, found, raised_error_flag). raised_error_flag=True
# distinguishes "DB error" from "no rows" so callers can log/metric.
ProbeFunc = Callable[
    [str, str, str, str],  # resource_type, resource_id, source_version, locale
    Awaitable[tuple[Optional[str], bool, bool]],
]


# The asyncpg-style fetchval shape we use. Lets tests inject a fake
# pool without spinning up real asyncpg. Mirrors _Acquirer in
# override_pgx.py.
class _Acquirer(Protocol):
    async def fetchval(self, query: str, *args: Any) -> Any: ...


_LOOKUP_QUERY = """
    SELECT translated_text
      FROM localization.dynamic_translations
     WHERE resource_type   = $1
       AND resource_id     = $2
       AND source_version  = $3
       AND language_code   = $4
       AND status         IN ('override', 'approved')
     ORDER BY CASE status WHEN 'override' THEN 0 ELSE 1 END
     LIMIT 1
"""


async def _pool_probe(
    pool: _Acquirer,
    resource_type: str,
    resource_id: str,
    source_version: str,
    locale: str,
) -> tuple[Optional[str], bool, bool]:
    """Production probe — asyncpg fetchval against
    localization.dynamic_translations. Same shape as
    overridepgx.PgxOverrideStore.lookup; see that module for status +
    source_version filter rationale.

    Returns (value, found, error_flag). error_flag=True means a DB
    error fired; caller MUST still degrade to the seed but may want
    to log/metric the failure.
    """
    try:
        value = await pool.fetchval(
            _LOOKUP_QUERY,
            resource_type,
            resource_id,
            source_version,
            locale,
        )
    except Exception:  # noqa: BLE001 — degrade, never propagate
        logger.exception(
            "DynamicRegistry probe failed",
            extra={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "locale": locale,
            },
        )
        return None, False, True
    if value is None:
        return None, False, False
    return str(value), True, False


class DynamicRegistry:
    """Async registry that composes a seed with a runtime-override layer.

    Construction::

        from kielo_shared.localization.support_registry import MapRegistry
        from kielo_shared.localization.dynamic_registry import (
            DynamicRegistry, AsyncRedisCache,
        )

        seed = MapRegistry(supported_locales_in=["en", "vi"])
        seed.set("ui.greeting", "en", "Hello")
        seed.set("ui.greeting", "vi", "Xin chào")
        seed.finalize()

        cache = AsyncRedisCache(redis_client)
        registry = DynamicRegistry(seed=seed, pool=asyncpg_pool, cache=cache)

        # Async path picks up overrides:
        text = await registry.aresolve("ui.greeting", "vi")
        # Sync path bypasses overrides:
        text_sync = registry.resolve("ui.greeting", "vi")  # always seed

    Parameters mirror the Go ``New`` constructor.
    """

    # The asyncpg pool is typed as _Acquirer; production wires
    # an asyncpg.Pool, tests wire a stub.
    def __init__(
        self,
        *,
        seed: SupportRegistry,
        pool: Optional[_Acquirer] = None,
        cache: Optional[AsyncCache] = None,
        hit_ttl_seconds: int = DEFAULT_HIT_TTL_SECONDS,
        miss_ttl_seconds: int = DEFAULT_MISS_TTL_SECONDS,
        resource_type: str = UI_STRING,
        probe: Optional[ProbeFunc] = None,
    ) -> None:
        self._seed = seed
        self._cache = cache
        self._hit_ttl = max(1, hit_ttl_seconds)
        self._miss_ttl = max(1, miss_ttl_seconds)
        self._resource_type = resource_type
        self._key_prefix = f"dynreg:v1:{resource_type}:"
        self._source_version_memo: dict[str, str] = {}
        self._missing_source_memo: set[str] = set()
        # probe parameter is the test injection seam; pool is the
        # production wiring. They are mutually exclusive — if probe
        # is supplied, pool is ignored.
        if probe is not None:
            self._probe: Optional[ProbeFunc] = probe
        elif pool is not None:
            async def _bound_probe(
                rt: str, rid: str, sv: str, loc: str
            ) -> tuple[Optional[str], bool, bool]:
                return await _pool_probe(pool, rt, rid, sv, loc)
            self._probe = _bound_probe
        else:
            self._probe = None

    # ----- Sync surface (delegates to seed; overrides not applied) ----
    # The sync path is for module-load-time resolution and tests. It
    # intentionally bypasses the override layer because there's no
    # blocking way to run an async DB probe without violating asyncio
    # semantics. Callers that want overrides MUST use aresolve.

    def resolve(self, key: str, support_locale: str) -> str:
        return self._seed.resolve(key, support_locale)

    def resolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str:
        return self._seed.resolve_template(key, support_locale, **params)

    # ----- Async surface (override-aware) -----

    async def aresolve(self, key: str, support_locale: str) -> str:
        """Async resolve with runtime-override probe.

        Probe order:
          1. Source-version compute (memoized). If the seed has no
             English text for this key, skip the override layer.
          2. English locale → return seed value (no probe; the
             English seed IS the source-of-truth for overrides).
          3. Cache: hit → return; cached-negative → seed fallback.
          4. DB probe via _probe. Hit → cache + return.
             Miss/error → cache-negative + seed fallback.
        """
        source_version, source_text, has_source = self._source_version_for(key)
        if not has_source:
            return self._seed.resolve(key, support_locale)

        normalized = _normalize(support_locale)
        if not normalized:
            return self._seed.resolve(key, support_locale)
        if normalized == FALLBACK_LOCALE:
            # English seed is the source-of-truth; never probe.
            return source_text

        cache_key = self._cache_key_for(key, source_version, normalized)

        if self._cache is not None:
            value, is_override, cached_ok = await self._cache.get(cache_key)
            if cached_ok:
                if is_override and value is not None:
                    return value
                # Cached-negative.
                return self._seed.resolve(key, support_locale)

        # Cache miss → probe DB.
        if self._probe is not None:
            value, found, error_flag = await self._probe(
                self._resource_type, key, source_version, normalized
            )
            if found and value is not None and not error_flag:
                if self._cache is not None:
                    await self._cache.set(cache_key, value, self._hit_ttl)
                return value
            # Miss or DB error → cache-negative + seed fallback.
            if self._cache is not None:
                await self._cache.set_negative(cache_key, self._miss_ttl)
            return self._seed.resolve(key, support_locale)

        # No probe configured → degrade to seed.
        return self._seed.resolve(key, support_locale)

    async def aresolve_template(
        self, key: str, support_locale: str, /, **params: object
    ) -> str:
        """Async resolve + ``str.format_map`` substitution. Mirrors
        ``MapRegistry.resolve_template`` but uses the override-aware
        ``aresolve`` to fetch the source text."""
        text = await self.aresolve(key, support_locale)
        if "{" not in text:
            return text
        try:
            return _SafeFormatter().vformat(text, (), params)
        except (KeyError, IndexError, ValueError) as exc:
            logger.warning(
                "DynamicRegistry template parse failed for key=%s locale=%s: %s",
                key, support_locale, exc,
            )
            return text

    def supported_locales(self) -> list[str]:
        return self._seed.supported_locales()

    def coverage_report(self) -> dict[str, CoverageStats]:
        # Phase 5 pilot: return seed report unchanged. Filling
        # CoverageStats.overridden from the DB is a follow-up
        # (matches the Go side's behaviour).
        return self._seed.coverage_report()

    # ----- internals -----

    def _source_version_for(self, key: str) -> tuple[str, str, bool]:
        """Return ``(source_version, english_seed_text, has_source)``.
        Memoized — first call computes sha256[:16], later calls are
        dict reads. ``has_source=False`` means the seed has no English
        value (registry.resolve returns the key string)."""
        if key in self._missing_source_memo:
            return "", "", False
        if key in self._source_version_memo:
            # Recompute english text — it's just a dict lookup on the
            # seed, no need to memoize separately.
            english = self._seed.resolve(key, FALLBACK_LOCALE)
            return self._source_version_memo[key], english, english != key

        english = self._seed.resolve(key, FALLBACK_LOCALE)
        if english == key:
            self._missing_source_memo.add(key)
            return "", "", False

        digest = hashlib.sha256(english.encode("utf-8")).hexdigest()
        source_version = digest[:16]
        self._source_version_memo[key] = source_version
        return source_version, english, True

    def _cache_key_for(
        self, resource_id: str, source_version: str, locale: str
    ) -> str:
        return f"{self._key_prefix}{resource_id}:{source_version}:{locale}"


# ---------------------------------------------------------------------------
# Cache implementations
# ---------------------------------------------------------------------------


class NoopAsyncCache:
    """AsyncCache that never caches. Useful for tests and
    strict-consistency mode. Always reports cache miss."""

    async def get(
        self, key: str
    ) -> tuple[Optional[str], bool, bool]:
        return None, False, False

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        return None

    async def set_negative(self, key: str, ttl_seconds: int) -> None:
        return None


class AsyncRedisCache:
    """Async-redis-backed AsyncCache implementation.

    Adapter, not a client: callers supply their own ``redis.asyncio.Redis``
    (or compatible). The package owns the GET/SET semantics only.

    Storage shape: positive hits → raw override text. Negative hits →
    ``_NEGATIVE_SENTINEL``. TTL applied per Set call.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    async def get(
        self, key: str
    ) -> tuple[Optional[str], bool, bool]:
        try:
            value = await self._client.get(key)
        except Exception:  # noqa: BLE001 — degrade
            logger.exception("AsyncRedisCache.get failed", extra={"key": key})
            return None, False, False
        if value is None:
            return None, False, False
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if value == _NEGATIVE_SENTINEL:
            return None, False, True
        return value, True, True

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        try:
            await self._client.set(key, value, ex=ttl_seconds)
        except Exception:  # noqa: BLE001
            logger.exception("AsyncRedisCache.set failed", extra={"key": key})

    async def set_negative(self, key: str, ttl_seconds: int) -> None:
        try:
            await self._client.set(key, _NEGATIVE_SENTINEL, ex=ttl_seconds)
        except Exception:  # noqa: BLE001
            logger.exception(
                "AsyncRedisCache.set_negative failed", extra={"key": key}
            )
