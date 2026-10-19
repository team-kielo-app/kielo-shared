from __future__ import annotations

from typing import Any

import pytest

from kielo_shared.localization.cache import RedisCacheDecorator, _key_for
from kielo_shared.localization.types import TranslationItem, TranslationResult

TTL = 123


class _Pipe:
    def __init__(self, parent: _CountingRedis, fail: bool) -> None:
        self._parent = parent
        self._ops: list[tuple[str, int | None]] = []
        self._fail = fail

    def set(self, key: str, value: str, ex: int | None = None) -> _Pipe:
        self._ops.append((key, ex))
        self._parent.pending[key] = value
        return self

    async def execute(self) -> list[Any]:
        self._parent.round_trips += 1
        self._parent.pipeline_executes += 1
        if self._fail:
            raise ConnectionError("down")
        for key, ex in self._ops:
            self._parent.data[key] = self._parent.pending.pop(key)
            self._parent.ttls[key] = ex
        return [True] * len(self._ops)


class _CountingRedis:
    def __init__(self, data: dict[str, Any] | None = None, down: bool = False) -> None:
        self.data: dict[str, Any] = dict(data or {})
        self.ttls: dict[str, int | None] = {}
        self.pending: dict[str, str] = {}
        self.round_trips = 0
        self.mgets = 0
        self.gets = 0
        self.sets = 0
        self.pipeline_executes = 0
        self.down = down

    async def mget(self, keys: list[str]) -> list[Any]:
        self.round_trips += 1
        self.mgets += 1
        if self.down:
            raise ConnectionError("down")
        return [self.data.get(k) for k in keys]

    async def get(self, key: str) -> Any:
        self.gets += 1
        return self.data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> Any:
        self.sets += 1

    def pipeline(self, transaction: bool = True) -> _Pipe:
        assert transaction is False
        return _Pipe(self, self.down)


class _Inner:
    provider_id = "stub:v1"

    def __init__(self, provider: str = "stub:v1") -> None:
        self.calls: list[list[str]] = []
        self._provider = provider

    async def translate_batch(
        self, items, *, source_locale, target_locale, idempotency_key=None
    ):
        self.calls.append([i.text for i in items])
        return [
            TranslationResult(text=f"T({i.text})", provider=self._provider)
            for i in items
        ]


def _key(text: str) -> str:
    return _key_for(
        provider_id="stub:v1",
        source_locale="fi",
        target_locale="en",
        item=TranslationItem(text=text),
    )


async def _run(dec: RedisCacheDecorator, texts: list[str]) -> list[TranslationResult]:
    return await dec.translate_batch(
        [TranslationItem(text=t) for t in texts], source_locale="fi", target_locale="en"
    )


@pytest.mark.asyncio
async def test_batch_is_one_mget_and_one_pipeline_with_ttl() -> None:
    redis = _CountingRedis()
    inner = _Inner()
    dec = RedisCacheDecorator(inner, redis, ttl_sec=TTL)
    out = await _run(dec, [f"w{i}" for i in range(10)])
    assert [r.text for r in out] == [f"T(w{i})" for i in range(10)]
    assert (redis.mgets, redis.pipeline_executes, redis.gets, redis.sets) == (
        1,
        1,
        0,
        0,
    )
    assert redis.round_trips == 2
    assert len(redis.data) == 10 and set(redis.ttls.values()) == {TTL}


@pytest.mark.asyncio
async def test_mixed_hits_and_misses_keep_order() -> None:
    redis = _CountingRedis({_key("b"): "CACHED-b", _key("d"): b"CACHED-d"})
    inner = _Inner()
    dec = RedisCacheDecorator(inner, redis, ttl_sec=TTL)
    out = await _run(dec, ["a", "b", "c", "d", "e"])
    assert [r.text for r in out] == ["T(a)", "CACHED-b", "T(c)", "CACHED-d", "T(e)"]
    assert [r.cached for r in out] == [False, True, False, True, False]
    assert inner.calls == [["a", "c", "e"]]
    assert redis.mgets == 1 and redis.pipeline_executes == 1
    assert set(redis.data) >= {_key("a"), _key("c"), _key("e")}


@pytest.mark.asyncio
async def test_all_hits_skip_inner_and_pipeline() -> None:
    redis = _CountingRedis({_key("a"): "x", _key("b"): "y"})
    inner = _Inner()
    out = await _run(RedisCacheDecorator(inner, redis), ["a", "b"])
    assert [r.text for r in out] == ["x", "y"]
    assert inner.calls == [] and redis.pipeline_executes == 0 and redis.round_trips == 1


@pytest.mark.asyncio
async def test_passthrough_results_are_not_cached() -> None:
    redis = _CountingRedis()
    out = await _run(RedisCacheDecorator(_Inner("passthrough"), redis), ["a", "b"])
    assert [r.text for r in out] == ["T(a)", "T(b)"]
    assert redis.pipeline_executes == 0 and not redis.data


@pytest.mark.asyncio
async def test_redis_down_fails_open() -> None:
    redis = _CountingRedis(down=True)
    inner = _Inner()
    out = await _run(RedisCacheDecorator(inner, redis), ["a", "b"])
    assert [r.text for r in out] == ["T(a)", "T(b)"]
    assert inner.calls == [["a", "b"]]


@pytest.mark.asyncio
async def test_client_without_mget_or_pipeline_falls_back_to_per_key() -> None:
    class Plain:
        def __init__(self) -> None:
            self.d: dict[str, str] = {}

        async def get(self, key: str) -> Any:
            return self.d.get(key)

        async def set(self, key: str, value: str, ex: int | None = None) -> Any:
            self.d[key] = value

    plain = Plain()
    dec = RedisCacheDecorator(_Inner(), plain)
    assert [r.text for r in await _run(dec, ["a", "b"])] == ["T(a)", "T(b)"]
    out = await _run(dec, ["a", "b"])
    assert [r.cached for r in out] == [True, True]
