"""Tests for kielo_shared.localization.dynamic_registry.

Mirrors the Go contract tests at
kielo-shared/locale/supportregistry/dynamicregistry/registry_test.go.
Every Go test has a Python equivalent so behavior stays parallel
across the language boundary.
"""
from __future__ import annotations

import hashlib
from typing import Optional

import pytest

from kielo_shared.localization.dynamic_registry import (
    DynamicRegistry,
    NoopAsyncCache,
    AsyncRedisCache,
)
from kielo_shared.localization.support_registry import MapRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_seed() -> MapRegistry:
    """Returns a finalized MapRegistry with three keys across en/vi/sv:
    greeting (all 3), farewell (en+vi only). ui.unknown is absent so
    the 'no English seed → skip override layer' branch is exercisable.
    """
    r = MapRegistry(supported_locales_in=["en", "vi", "sv"])
    assert r.set("ui.greeting", "en", "Hello")
    assert r.set("ui.greeting", "vi", "Xin chào")
    assert r.set("ui.greeting", "sv", "Hej")
    assert r.set("ui.farewell", "en", "Goodbye")
    assert r.set("ui.farewell", "vi", "Tạm biệt")
    r.finalize()
    return r


class StubCache:
    """Controllable AsyncCache for assertions."""

    def __init__(self) -> None:
        # key → ("" for negative, str for positive)
        self.store: dict[str, str] = {}
        self.get_calls = 0
        self.set_calls = 0
        self.set_negative_calls = 0

    async def get(
        self, key: str
    ) -> tuple[Optional[str], bool, bool]:
        self.get_calls += 1
        if key not in self.store:
            return None, False, False
        v = self.store[key]
        if v == "":
            return None, False, True  # cached-negative
        return v, True, True

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self.set_calls += 1
        self.store[key] = value

    async def set_negative(self, key: str, ttl_seconds: int) -> None:
        self.set_negative_calls += 1
        self.store[key] = ""


class StubProbe:
    """Controllable probe function with hit/miss/error per-key configs."""

    def __init__(self) -> None:
        self.results: dict[tuple[str, str, str], tuple[Optional[str], bool, bool]] = {}
        self.calls = 0

    def set_hit(self, resource_id: str, source_version: str, locale: str, value: str) -> None:
        self.results[(resource_id, source_version, locale)] = (value, True, False)

    def set_miss(self, resource_id: str, source_version: str, locale: str) -> None:
        self.results[(resource_id, source_version, locale)] = (None, False, False)

    def set_error(self, resource_id: str, source_version: str, locale: str) -> None:
        self.results[(resource_id, source_version, locale)] = (None, False, True)

    async def probe(
        self,
        resource_type: str,
        resource_id: str,
        source_version: str,
        locale: str,
    ) -> tuple[Optional[str], bool, bool]:
        self.calls += 1
        # Default → miss when not preconfigured.
        return self.results.get(
            (resource_id, source_version, locale), (None, False, False)
        )


def _sv_for(english: str) -> str:
    """Replicate the source_version hashing externally so tests can
    set probe results without going through the registry."""
    return hashlib.sha256(english.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aresolve_pool_none_degrades_to_seed():
    """No pool + no cache → pure pass-through over seed. Critical for
    services that haven't yet wired the DB."""
    r = DynamicRegistry(seed=_build_seed())
    assert await r.aresolve("ui.greeting", "vi") == "Xin chào"
    assert await r.aresolve("ui.greeting", "sv") == "Hej"
    assert await r.aresolve("ui.greeting", "en") == "Hello"
    # Missing key returns key string verbatim.
    assert await r.aresolve("ui.unknown", "vi") == "ui.unknown"


@pytest.mark.asyncio
async def test_aresolve_english_locale_shortcuts_to_seed():
    """English overrides aren't probed — the English seed IS the
    source-of-truth for overrides. Must not touch cache or DB."""
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=_build_seed(), cache=cache, probe=probe.probe)

    got = await r.aresolve("ui.greeting", "en")
    assert got == "Hello"
    assert cache.get_calls == 0, "cache must not be consulted for en"
    assert probe.calls == 0, "DB must not be probed for en"


@pytest.mark.asyncio
async def test_aresolve_empty_locale_shortcuts_to_seed():
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=_build_seed(), cache=cache, probe=probe.probe)

    got = await r.aresolve("ui.greeting", "")
    assert got == "Hello"
    assert cache.get_calls == 0
    assert probe.calls == 0


@pytest.mark.asyncio
async def test_aresolve_key_absent_from_seed_skips_override_layer():
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=_build_seed(), cache=cache, probe=probe.probe)

    got = await r.aresolve("ui.missing", "vi")
    assert got == "ui.missing"
    assert cache.get_calls == 0
    assert probe.calls == 0


@pytest.mark.asyncio
async def test_aresolve_cache_hit_positive_returns_override():
    seed = _build_seed()
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Hello")
    cache_key = f"dynreg:v1:ui.string:ui.greeting:{sv}:vi"
    cache.store[cache_key] = "Chào bạn!"

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Chào bạn!", "cached override must win over seed value"
    assert probe.calls == 0, "DB must not be probed on cache hit"


@pytest.mark.asyncio
async def test_aresolve_cache_hit_negative_falls_through_to_seed():
    seed = _build_seed()
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Hello")
    cache_key = f"dynreg:v1:ui.string:ui.greeting:{sv}:vi"
    cache.store[cache_key] = ""  # cached-negative

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Xin chào"
    assert probe.calls == 0


@pytest.mark.asyncio
async def test_aresolve_cache_miss_db_hit_caches_and_returns_override():
    seed = _build_seed()
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Hello")
    probe.set_hit("ui.greeting", sv, "vi", "Xin chào em!")

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Xin chào em!"
    assert probe.calls == 1
    assert cache.set_calls == 1, "positive hit must be cached"

    # Second call should be served from cache, no further DB probe.
    got2 = await r.aresolve("ui.greeting", "vi")
    assert got2 == "Xin chào em!"
    assert probe.calls == 1, "second call must not re-probe DB"


@pytest.mark.asyncio
async def test_aresolve_cache_miss_db_miss_caches_negative_and_returns_seed():
    seed = _build_seed()
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Hello")
    probe.set_miss("ui.greeting", sv, "vi")

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Xin chào"
    assert probe.calls == 1
    assert cache.set_negative_calls == 1

    got2 = await r.aresolve("ui.greeting", "vi")
    assert got2 == "Xin chào"
    assert probe.calls == 1, "cached-negative must skip the DB probe"


@pytest.mark.asyncio
async def test_aresolve_db_error_degrades_to_seed_and_caches_negative():
    """DB error path: caller MUST get the seed value, and the
    error MUST cache-negative so we don't hammer the DB during outage."""
    seed = _build_seed()
    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Hello")
    probe.set_error("ui.greeting", sv, "vi")

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Xin chào"
    assert cache.set_negative_calls == 1


@pytest.mark.asyncio
async def test_aresolve_no_cache_still_works():
    """cache=None: DynamicRegistry still functions, just hits DB
    on every aresolve. Useful for strict-consistency migration tools."""
    seed = _build_seed()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, probe=probe.probe)

    sv = _sv_for("Hello")
    probe.set_hit("ui.greeting", sv, "vi", "Override")

    got = await r.aresolve("ui.greeting", "vi")
    assert got == "Override"
    got2 = await r.aresolve("ui.greeting", "vi")
    assert got2 == "Override"
    assert probe.calls == 2, "no cache → every aresolve probes DB"


def test_source_version_is_memoized():
    """Hash + hex encode is cheap but it's per-aresolve. Memoize
    after the first lookup."""
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    sv1, _, has1 = r._source_version_for("ui.greeting")
    sv2, _, has2 = r._source_version_for("ui.greeting")
    assert has1 and has2
    assert sv1 == sv2
    assert sv1 == _sv_for("Hello")
    # Memo populated.
    assert "ui.greeting" in r._source_version_memo


def test_source_version_changes_when_english_seed_changes():
    """Different English text → different source_version → stale
    overrides become invisible (ADR-007 version gating)."""
    seed1 = MapRegistry(supported_locales_in=["en", "vi"])
    seed1.set("ui.greeting", "en", "Hello")
    seed1.set("ui.greeting", "vi", "Xin chào")
    seed1.finalize()
    r1 = DynamicRegistry(seed=seed1)
    sv1, _, _ = r1._source_version_for("ui.greeting")

    seed2 = MapRegistry(supported_locales_in=["en", "vi"])
    seed2.set("ui.greeting", "en", "Hello there")
    seed2.set("ui.greeting", "vi", "Xin chào")
    seed2.finalize()
    r2 = DynamicRegistry(seed=seed2)
    sv2, _, _ = r2._source_version_for("ui.greeting")

    assert sv1 != sv2


@pytest.mark.asyncio
async def test_aresolve_template_applies_params_after_override():
    seed = MapRegistry(supported_locales_in=["en", "vi"])
    seed.set("ui.welcome", "en", "Welcome {name}")
    seed.set("ui.welcome", "vi", "Chào {name}")
    seed.finalize()

    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Welcome {name}")
    probe.set_hit("ui.welcome", sv, "vi", "Xin chào {name}!")

    got = await r.aresolve_template("ui.welcome", "vi", name="Khanh")
    assert got == "Xin chào Khanh!"


@pytest.mark.asyncio
async def test_aresolve_template_no_override_applies_params_to_seed():
    seed = MapRegistry(supported_locales_in=["en", "vi"])
    seed.set("ui.welcome", "en", "Welcome {name}")
    seed.set("ui.welcome", "vi", "Chào {name}")
    seed.finalize()

    cache = StubCache()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, cache=cache, probe=probe.probe)

    sv = _sv_for("Welcome {name}")
    probe.set_miss("ui.welcome", sv, "vi")

    got = await r.aresolve_template("ui.welcome", "vi", name="Khanh")
    assert got == "Chào Khanh"


def test_sync_resolve_bypasses_override_layer():
    """The sync path delegates straight to the seed. This is the
    deliberate design — overrides require an async context."""
    seed = _build_seed()
    probe = StubProbe()
    r = DynamicRegistry(seed=seed, probe=probe.probe)

    sv = _sv_for("Hello")
    probe.set_hit("ui.greeting", sv, "vi", "OVERRIDE")

    # Sync resolve returns seed even when an override is configured.
    assert r.resolve("ui.greeting", "vi") == "Xin chào"
    assert probe.calls == 0, "sync resolve must not probe DB"


def test_supported_locales_pass_through_to_seed():
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    assert sorted(r.supported_locales()) == ["en", "sv", "vi"]


def test_sync_coverage_report_passes_through_to_seed():
    # The sync surface intentionally bypasses the override layer
    # (mirror of the sync resolve/resolve_template path); admin
    # callers that need the DB-augmented numbers must await
    # acoverage_report() instead.
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    assert r.coverage_report() == seed.coverage_report()


def test_custom_resource_type():
    seed = _build_seed()
    r = DynamicRegistry(seed=seed, resource_type="custom.type")
    assert r._resource_type == "custom.type"
    assert r._key_prefix == "dynreg:v1:custom.type:"


def test_custom_ttls():
    seed = _build_seed()
    r = DynamicRegistry(
        seed=seed,
        hit_ttl_seconds=600,
        miss_ttl_seconds=60,
    )
    assert r._hit_ttl == 600
    assert r._miss_ttl == 60


@pytest.mark.asyncio
async def test_noop_cache_always_misses():
    cache = NoopAsyncCache()
    v, is_override, cached_ok = await cache.get("k")
    assert v is None and is_override is False and cached_ok is False
    # set / set_negative are no-ops.
    await cache.set("k", "v", 60)
    await cache.set_negative("k", 60)


# ---------------------------------------------------------------------------
# AsyncRedisCache smoke (with a stub client)
# ---------------------------------------------------------------------------


class StubRedisClient:
    """Minimal stub matching the subset of redis.asyncio.Redis we use."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.raise_on_get = False
        self.raise_on_set = False

    async def get(self, key: str) -> Optional[str]:
        if self.raise_on_get:
            raise RuntimeError("redis down")
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int) -> None:
        if self.raise_on_set:
            raise RuntimeError("redis down")
        self.store[key] = value


@pytest.mark.asyncio
async def test_async_redis_cache_round_trip():
    client = StubRedisClient()
    cache = AsyncRedisCache(client)

    await cache.set("k", "value", ttl_seconds=60)
    v, is_override, cached_ok = await cache.get("k")
    assert v == "value"
    assert is_override is True
    assert cached_ok is True


@pytest.mark.asyncio
async def test_async_redis_cache_negative_round_trip():
    client = StubRedisClient()
    cache = AsyncRedisCache(client)

    await cache.set_negative("k", ttl_seconds=30)
    v, is_override, cached_ok = await cache.get("k")
    assert v is None
    assert is_override is False
    assert cached_ok is True


@pytest.mark.asyncio
async def test_async_redis_cache_miss():
    client = StubRedisClient()
    cache = AsyncRedisCache(client)

    v, is_override, cached_ok = await cache.get("k")
    assert v is None
    assert is_override is False
    assert cached_ok is False


@pytest.mark.asyncio
async def test_async_redis_cache_get_degrades_on_redis_error():
    """Cache.get MUST degrade to miss on Redis error so the
    registry falls through to DB probe rather than crashing."""
    client = StubRedisClient()
    client.raise_on_get = True
    cache = AsyncRedisCache(client)

    v, is_override, cached_ok = await cache.get("k")
    assert v is None
    assert is_override is False
    assert cached_ok is False


@pytest.mark.asyncio
async def test_async_redis_cache_set_swallows_error():
    """Cache.set on Redis error MUST NOT propagate — caller already
    has the override value; failing to cache it is recoverable."""
    client = StubRedisClient()
    client.raise_on_set = True
    cache = AsyncRedisCache(client)

    # Must not raise.
    await cache.set("k", "v", ttl_seconds=60)
    await cache.set_negative("k", ttl_seconds=30)


# ---------------------------------------------------------------------------
# acoverage_report — DB-augmented per-locale Overridden counts
# ---------------------------------------------------------------------------
#
# Mirrors the Go CoverageReport tests in
# kielo-shared/locale/supportregistry/dynamicregistry/registry_test.go.
# Every Go assertion has a Python equivalent so behavior stays parallel.


class StubCoverageProbe:
    """Controllable coverage_probe for acoverage_report tests."""

    def __init__(self) -> None:
        self.counts: dict[tuple[str, str], int] = {}
        self.error: Optional[Exception] = None
        self.calls = 0

    async def probe(
        self, resource_type: str
    ) -> dict[tuple[str, str], int]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return dict(self.counts)


async def _warm_key(r: DynamicRegistry, key: str) -> None:
    """Force `key` into the source-version memo so acoverage_report's
    seed-key filter sees it. Mirrors the Go warmKey helper — real
    production traffic warms the memo via aresolve; tests short-circuit
    by computing the source_version directly through the internal API.
    """
    # The internal _source_version_for is the canonical memo-warmer;
    # calling aresolve(key, "en") would also work but adds an extra
    # path that isn't needed for memo seeding.
    r._source_version_for(key)


@pytest.mark.asyncio
async def test_acoverage_report_no_probe_returns_seed_report_unchanged():
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)  # pool=None → no coverage_probe wired
    got = await r.acoverage_report()
    assert got == seed.coverage_report(), (
        "acoverage_report without a coverage_probe must pass the seed's report through"
    )


@pytest.mark.asyncio
async def test_acoverage_report_overridden_counts_bump_per_locale():
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    await _warm_key(r, "ui.greeting")
    await _warm_key(r, "ui.farewell")

    # Two override rows for vi, one for sv. Same shape as the Go test.
    stub = StubCoverageProbe()
    stub.counts = {
        ("ui.greeting", "vi"): 1,
        ("ui.farewell", "vi"): 1,
        ("ui.greeting", "sv"): 1,
    }
    r._coverage_probe = stub.probe  # type: ignore[assignment]

    got = await r.acoverage_report()
    assert stub.calls == 1, "exactly one aggregate query per acoverage_report call"
    assert got["vi"].overridden == 2, "vi should have 2 overridden keys"
    assert got["sv"].overridden == 1, "sv should have 1 overridden key"
    # English is the canonical source-of-truth for overrides; the
    # registry never serves an en override (see aresolve's
    # FALLBACK_LOCALE shortcut), so the count stays 0 by construction.
    assert got["en"].overridden == 0, "en is the canonical source; overridden stays 0"


@pytest.mark.asyncio
async def test_acoverage_report_ignores_override_rows_for_keys_not_in_seed():
    # Defensive: if a previous release had a key 'ui.deprecated' that
    # was removed in this release, override rows in the DB for that
    # key shouldn't inflate the per-locale Overridden count — those
    # rows are stale and the seam won't serve them anyway.
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    await _warm_key(r, "ui.greeting")

    stub = StubCoverageProbe()
    stub.counts = {
        ("ui.greeting", "vi"): 1,    # in seed → counted
        ("ui.deprecated", "vi"): 1,  # NOT in seed → ignored
    }
    r._coverage_probe = stub.probe  # type: ignore[assignment]

    got = await r.acoverage_report()
    assert got["vi"].overridden == 1, (
        "ui.deprecated has no seed entry; its override row must NOT count"
    )


@pytest.mark.asyncio
async def test_acoverage_report_probe_error_degrades_to_seed_report():
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    await _warm_key(r, "ui.greeting")

    stub = StubCoverageProbe()
    stub.error = RuntimeError("simulated DB failure")
    r._coverage_probe = stub.probe  # type: ignore[assignment]

    got = await r.acoverage_report()
    # Failure mode: returns the seed report unchanged. The admin grid
    # prefers "Overridden: 0 (probe failed)" over "no data at all".
    assert got == seed.coverage_report()


@pytest.mark.asyncio
async def test_acoverage_report_empty_memo_skips_probe_filter():
    # A freshly-constructed registry that hasn't served any aresolve
    # traffic has an empty source_version_memo. The probe still runs
    # (one aggregate query), but the seed-key filter rejects every
    # row, so all per-locale Overridden counts stay 0. Mirrors the Go
    # registry.collectSeedKeys "empty memo → seed report" branch.
    seed = _build_seed()
    r = DynamicRegistry(seed=seed)
    # Deliberately do NOT warm any key.

    stub = StubCoverageProbe()
    stub.counts = {("ui.greeting", "vi"): 1}
    r._coverage_probe = stub.probe  # type: ignore[assignment]

    got = await r.acoverage_report()
    # Returns the seed's report unchanged because the memo is empty
    # and we skip the augmentation step entirely.
    assert got == seed.coverage_report()


@pytest.mark.asyncio
async def test_acoverage_report_does_not_mutate_seed_stats():
    # The seed's CoverageStats objects may be cached internally;
    # acoverage_report must build fresh dataclasses rather than
    # mutating shared state. Pinned by checking the seed's
    # coverage_report() returns identical values BEFORE and AFTER
    # the async call.
    seed = _build_seed()
    seed_before = seed.coverage_report()

    r = DynamicRegistry(seed=seed)
    await _warm_key(r, "ui.greeting")
    stub = StubCoverageProbe()
    stub.counts = {("ui.greeting", "vi"): 1}
    r._coverage_probe = stub.probe  # type: ignore[assignment]

    _ = await r.acoverage_report()
    seed_after = seed.coverage_report()
    assert seed_before == seed_after, (
        "acoverage_report must not mutate the seed's CoverageStats objects"
    )
