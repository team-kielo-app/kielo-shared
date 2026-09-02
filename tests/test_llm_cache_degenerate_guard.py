"""Degenerate LLM responses ("[]", "{}", "null") must never be cached.

A degenerate-but-non-empty response is a failed generation wearing valid
JSON. Caching one poisons the key for the whole TTL: every retry is an
instant hit on the same garbage, and callers whose retry pools retain
failures (grammar-example enrichment) then self-select for poisoned keys —
prod ran failed=10/10 nightly for weeks (diagnosed 2026-09-02).

The guard is WRITE-side only: an already-poisoned entry still hits until it
expires or the caller bumps prompt_version (the enrichment fix does both).
"""
from __future__ import annotations

import pytest

from kielo_shared.llm.cache import LLMCacheDecorator, _cacheable_text
from kielo_shared.llm.types import LLMRequest, LLMResult


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.sets: list[str] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        self.sets.append(key)


class _FakeProvider:
    def __init__(self, text: str):
        self._text = text
        self.calls = 0

    @property
    def provider_id(self) -> str:
        return "fake:model"

    async def generate(self, request: LLMRequest) -> LLMResult:
        self.calls += 1
        return LLMResult(text=self._text, provider=self.provider_id, cached=False)


def _request(**overrides) -> LLMRequest:
    defaults = dict(
        system_prompt="s",
        user_prompt="u",
        task="t",
        prompt_version="v1",
        cache_policy="read_write",
        cache_key="k",
    )
    defaults.update(overrides)
    return LLMRequest(**defaults)


@pytest.mark.parametrize("degenerate", ["[]", "{}", "null", " [] ", "NULL", ""])
@pytest.mark.asyncio
async def test_degenerate_text_is_not_cached(degenerate):
    redis = _FakeRedis()
    provider = _FakeProvider(degenerate)
    cache = LLMCacheDecorator(provider, redis)

    result = await cache.generate(_request())
    assert result.text == degenerate
    assert redis.sets == [], f"degenerate {degenerate!r} must not be cached"

    # And the next call goes to the provider again — a miss, not a hit.
    await cache.generate(_request())
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_real_payload_is_cached_and_hit():
    redis = _FakeRedis()
    provider = _FakeProvider('[{"text": "Minä ostin kirjan.", "translation": "I bought a book."}]')
    cache = LLMCacheDecorator(provider, redis)

    first = await cache.generate(_request())
    assert not first.cached and len(redis.sets) == 1

    second = await cache.generate(_request())
    assert second.cached and provider.calls == 1


def test_cacheable_text_table():
    assert not _cacheable_text(None)
    assert not _cacheable_text("   ")
    assert not _cacheable_text("[]")
    assert not _cacheable_text("None")
    assert _cacheable_text('[{"text": "x"}]')


@pytest.mark.asyncio
async def test_degenerate_ok_metadata_opts_into_caching():
    """Tasks where a degenerate value IS a valid result (extraction that
    legitimately finds nothing) opt out per-request; empty text stays
    uncacheable even then."""
    redis = _FakeRedis()
    provider = _FakeProvider("[]")
    cache = LLMCacheDecorator(provider, redis)

    await cache.generate(_request(metadata={"cache_degenerate_ok": True}))
    assert len(redis.sets) == 1, "opt-in degenerate result must be cached"

    empty_redis = _FakeRedis()
    empty_cache = LLMCacheDecorator(_FakeProvider(""), empty_redis)
    await empty_cache.generate(_request(metadata={"cache_degenerate_ok": True}))
    assert empty_redis.sets == []
