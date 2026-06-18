"""Sweep AAAAA: unit tests for RedisCache (Cache + BatchCache impl).

Uses a fake-Redis backed by an in-memory dict so we don't require a
real Redis server. The protocol is the same shape as
``redis.asyncio.Redis`` with ``decode_responses=True``.
"""

from __future__ import annotations

from typing import Any

import pytest

from kielo_shared.localization import BatchCache, Cache, RedisCache


class _FakePipeline:
    """Records commands; execute() returns the recorded results in order."""

    def __init__(self, parent: "_FakeRedis") -> None:
        self._parent = parent
        self._ops: list[tuple[str, tuple[Any, ...]]] = []

    def get(self, key: str) -> "_FakePipeline":
        self._ops.append(("get", (key,)))
        return self

    def set(
        self, key: str, value: str, ex: int | None = None
    ) -> "_FakePipeline":
        self._ops.append(("set", (key, value, ex)))
        return self

    def pttl(self, key: str) -> "_FakePipeline":
        self._ops.append(("pttl", (key,)))
        return self

    async def execute(self) -> list[Any]:
        results: list[Any] = []
        for op, args in self._ops:
            if op == "get":
                (key,) = args
                results.append(self._parent._data.get(key))
            elif op == "set":
                key, value, ex = args
                self._parent._data[key] = value
                if ex is not None:
                    self._parent._ttl[key] = ex
                self._parent.set_count += 1
            elif op == "pttl":
                (key,) = args
                ttl_s = self._parent._ttl.get(key)
                if key not in self._parent._data:
                    results.append(-2)
                elif ttl_s is None:
                    results.append(-1)
                else:
                    results.append(ttl_s * 1000)
        self._parent.pipeline_exec_count += 1
        return results


class _FakeRedis:
    """In-memory fake compatible with the RedisAsyncClient protocol."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        # ttl_seconds remaining per key. Use a stable initial value
        # for predictable age computation in tests.
        self._ttl: dict[str, int] = {}
        # Call counts so tests can assert ONE round-trip per phase.
        self.mget_count = 0
        self.pttl_count = 0
        self.set_count = 0
        self.get_count = 0
        self.pipeline_exec_count = 0

    async def get(self, key: str) -> Any:
        self.get_count += 1
        return self._data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> Any:
        self.set_count += 1
        self._data[key] = value
        if ex is not None:
            self._ttl[key] = ex
        return "OK"

    async def mget(self, keys: list[str]) -> list[Any]:
        self.mget_count += 1
        return [self._data.get(k) for k in keys]

    async def pttl(self, key: str) -> Any:
        self.pttl_count += 1
        if key not in self._data:
            return -2
        ttl_s = self._ttl.get(key)
        if ttl_s is None:
            return -1
        return ttl_s * 1000

    def pipeline(self, transaction: bool = False) -> _FakePipeline:
        return _FakePipeline(self)


# ============================================================================
# Protocol conformance
# ============================================================================


def test_redis_cache_implements_cache_and_batch_cache_protocols():
    """Compile-time assertion: RedisCache must satisfy both Cache and
    BatchCache protocols so the seam's runtime isinstance checks
    dispatch correctly."""
    cache = RedisCache(_FakeRedis(), total_ttl_seconds=3600.0)
    assert isinstance(cache, Cache)
    assert isinstance(cache, BatchCache)


# ============================================================================
# Single-key path
# ============================================================================


@pytest.mark.asyncio
async def test_set_then_get_roundtrip():
    client = _FakeRedis()
    cache = RedisCache(client, total_ttl_seconds=3600.0)
    await cache.set("k1", "v1", 3600.0)
    value, age = await cache.get("k1")
    assert value == "v1"
    assert age == 0.0  # freshly written


@pytest.mark.asyncio
async def test_get_miss_returns_none_none():
    cache = RedisCache(_FakeRedis(), total_ttl_seconds=3600.0)
    value, age = await cache.get("does-not-exist")
    assert value is None
    assert age is None


@pytest.mark.asyncio
async def test_get_handles_bytes_values():
    """redis.asyncio.Redis without decode_responses=True returns bytes;
    the cache must coerce to str."""
    client = _FakeRedis()
    # Pretend redis returned bytes for this key
    client._data["k1"] = b"hello"  # type: ignore[assignment]
    client._ttl["k1"] = 3600
    cache = RedisCache(client, total_ttl_seconds=3600.0)
    value, age = await cache.get("k1")
    assert value == "hello"


# ============================================================================
# Batch path — the AAAAA fast path
# ============================================================================


@pytest.mark.asyncio
async def test_batch_get_uses_one_mget_round_trip():
    client = _FakeRedis()
    cache = RedisCache(client, total_ttl_seconds=3600.0)
    # Seed 3 keys, leave 1 missing
    await cache.batch_set(
        {"k1": "v1", "k2": "v2", "k3": "v3"}, ttl_seconds=3600.0
    )
    initial_mget = client.mget_count
    initial_pttl = client.pttl_count
    initial_pipeline = client.pipeline_exec_count

    hits = await cache.batch_get(["k1", "k2", "missing", "k3"])

    # Sweep AAAAA invariant: ONE MGET regardless of N
    assert client.mget_count == initial_mget + 1
    # ONE pipelined PTTL exec for the 3 hits (not 3 separate PTTLs)
    assert client.pipeline_exec_count == initial_pipeline + 1
    assert client.pttl_count == initial_pttl  # no direct pttl calls

    assert set(hits.keys()) == {"k1", "k2", "k3"}
    assert "missing" not in hits
    assert hits["k1"].value == "v1"
    assert hits["k2"].value == "v2"
    assert hits["k3"].value == "v3"
    # Freshly written: age ≈ 0
    for entry in hits.values():
        assert entry.age_seconds == 0.0


@pytest.mark.asyncio
async def test_batch_get_empty_keys_returns_empty():
    cache = RedisCache(_FakeRedis(), total_ttl_seconds=3600.0)
    hits = await cache.batch_get([])
    assert hits == {}


@pytest.mark.asyncio
async def test_batch_get_all_misses_returns_empty():
    cache = RedisCache(_FakeRedis(), total_ttl_seconds=3600.0)
    hits = await cache.batch_get(["a", "b", "c"])
    assert hits == {}


@pytest.mark.asyncio
async def test_batch_set_uses_one_pipelined_exec():
    client = _FakeRedis()
    cache = RedisCache(client, total_ttl_seconds=3600.0)
    initial = client.pipeline_exec_count

    await cache.batch_set(
        {"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4"}, ttl_seconds=3600.0
    )

    # Sweep AAAAA invariant: ONE pipelined exec for N entries
    assert client.pipeline_exec_count == initial + 1
    # All 4 keys present + TTL set
    for k in ["k1", "k2", "k3", "k4"]:
        v, _ = await cache.get(k)
        assert v is not None


@pytest.mark.asyncio
async def test_batch_set_empty_dict_is_noop():
    client = _FakeRedis()
    cache = RedisCache(client, total_ttl_seconds=3600.0)
    initial = client.pipeline_exec_count
    await cache.batch_set({}, ttl_seconds=3600.0)
    assert client.pipeline_exec_count == initial


# ============================================================================
# Failure modes — must degrade gracefully (translation must not fail)
# ============================================================================


class _BrokenRedis:
    """All operations raise. RedisCache must catch + degrade."""

    async def get(self, key: str) -> Any:
        raise RuntimeError("redis down")

    async def set(self, key: str, value: str, ex: int | None = None) -> Any:
        raise RuntimeError("redis down")

    async def mget(self, keys: list[str]) -> list[Any]:
        raise RuntimeError("redis down")

    async def pttl(self, key: str) -> Any:
        raise RuntimeError("redis down")

    def pipeline(self, transaction: bool = False) -> Any:
        raise RuntimeError("redis down")


@pytest.mark.asyncio
async def test_get_swallows_errors():
    cache = RedisCache(_BrokenRedis(), total_ttl_seconds=3600.0)
    value, age = await cache.get("k1")
    assert value is None
    assert age is None


@pytest.mark.asyncio
async def test_batch_get_swallows_errors():
    cache = RedisCache(_BrokenRedis(), total_ttl_seconds=3600.0)
    hits = await cache.batch_get(["k1", "k2"])
    assert hits == {}


@pytest.mark.asyncio
async def test_set_swallows_errors():
    cache = RedisCache(_BrokenRedis(), total_ttl_seconds=3600.0)
    # Should not raise — Redis going down doesn't break translation.
    await cache.set("k1", "v1", 3600.0)


@pytest.mark.asyncio
async def test_batch_set_swallows_errors():
    cache = RedisCache(_BrokenRedis(), total_ttl_seconds=3600.0)
    await cache.batch_set({"k1": "v1"}, 3600.0)


# ============================================================================
# Age computation
# ============================================================================


@pytest.mark.asyncio
async def test_age_from_pttl_handles_special_values():
    """PTTL semantics:
       -2: key does not exist → age = total TTL (treat as expired)
       -1: key has no expiry  → age = 0 (treat as fresh)
       >=0: remaining ms       → age = total - pttl/1000
    """
    cache = RedisCache(_FakeRedis(), total_ttl_seconds=3600.0)
    # _age_from_pttl is intended to be private but it's worth testing.
    assert cache._age_from_pttl(-2) == 3600.0
    assert cache._age_from_pttl(-1) == 0.0
    assert cache._age_from_pttl(3600000) == 0.0  # full TTL remaining
    assert cache._age_from_pttl(1800000) == 1800.0  # half remaining
    assert cache._age_from_pttl(0) == 3600.0  # just expired
    # Bad input degrades to "expired"
    assert cache._age_from_pttl(None) == 3600.0
    assert cache._age_from_pttl("not-a-number") == 3600.0
