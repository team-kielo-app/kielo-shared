"""Tests for `kielo_shared.localization.seam`.

Mirrors `kielo-shared/localization/seam_test.go` so Python and Go services
exhibit identical resolution semantics (override → cache → provider with
single-flight + SWR). Pins every resolution branch via the CountingMetrics
counter so a regression that takes the wrong path fails CI even if the
output string happens to be correct.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from kielo_shared.localization.registry import LocalizationRegistry
from kielo_shared.localization.seam import (
    CountingMetrics,
    MapOverrideStore,
    NoopCache,
    Seam,
    SeamConfig,
    SourceRef,
    source_version_from_text,
)
from kielo_shared.localization.types import (
    TranslationItem,
    TranslationResult,
)


# ──────────────────────── Test harness ───────────────────────────────────


class StubProvider:
    """Provider that returns canned translations and tracks call count.
    Optional delay lets single-flight tests force a window in which
    sibling coroutines pile onto the in-flight call."""

    def __init__(self, translations: dict[str, str]) -> None:
        self._translations = translations
        self.calls = 0
        self.delay_seconds = 0.0
        self.raise_on_call = False

    @property
    def provider_id(self) -> str:
        return "stub-vi"

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        self.calls += 1
        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)
        if self.raise_on_call:
            raise RuntimeError("stub provider error")
        out: list[TranslationResult] = []
        for item in items:
            value = self._translations.get(f"{target_locale}|{item.text}", item.text)
            out.append(TranslationResult(
                text=value,
                provider=self.provider_id,
            ))
        return out


class FakeCache:
    """In-memory cache with controllable clock for SWR tests."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, float]] = {}
        self._now = 1_000_000.0

    def advance(self, seconds: float) -> None:
        self._now += seconds

    async def get(self, key: str) -> tuple[str | None, float | None]:
        entry = self._entries.get(key)
        if entry is None:
            return None, None
        value, written_at = entry
        return value, self._now - written_at

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        self._entries[key] = (value, self._now)


def _make_seam(
    *,
    provider: StubProvider | None = None,
    overrides: MapOverrideStore | None = None,
    cache: Any = None,
    fresh_ttl: float = 3600.0,
    stale_ttl: float = 86400.0,
) -> tuple[Seam, StubProvider, CountingMetrics, MapOverrideStore, Any]:
    provider = provider or StubProvider({
        "vi|Order a coffee": "Gọi một ly cà phê",
        "vi|Hello": "Xin chào",
    })
    registry = LocalizationRegistry()
    registry.register(provider.provider_id, provider)
    registry.route("en", "vi", provider.provider_id)
    overrides = overrides or MapOverrideStore()
    cache = cache if cache is not None else NoopCache()
    metrics = CountingMetrics()
    seam = Seam(
        registry,
        cache=cache,
        overrides=overrides,
        metrics=metrics,
        config=SeamConfig(fresh_ttl_seconds=fresh_ttl, stale_ttl_seconds=stale_ttl),
    )
    return seam, provider, metrics, overrides, cache


# ──────────────────────── passthrough ────────────────────────────────────


@pytest.mark.asyncio
async def test_english_is_passthrough() -> None:
    seam, provider, metrics, _, _ = _make_seam()
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Order a coffee"),
        target_locale="en",
    )
    assert got == "Order a coffee"
    assert provider.calls == 0
    assert metrics.count("convo.scenario.title", "en", "english_passthrough") == 1


@pytest.mark.asyncio
async def test_empty_target_locale_is_passthrough() -> None:
    seam, provider, _, _, _ = _make_seam()
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Hello"),
        target_locale="",
    )
    assert got == "Hello"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_empty_source_text_returns_empty() -> None:
    seam, provider, _, _, _ = _make_seam()
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text=""),
        target_locale="vi",
    )
    assert got == ""
    assert provider.calls == 0


# ──────────────────────── override ───────────────────────────────────────


@pytest.mark.asyncio
async def test_override_wins_over_provider() -> None:
    overrides = MapOverrideStore({
        "convo.scenario.title|s1|v1|vi": "Cốc cà phê admin-edited",
    })
    seam, provider, metrics, _, _ = _make_seam(overrides=overrides)
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Order a coffee"),
        target_locale="vi",
    )
    assert got == "Cốc cà phê admin-edited"
    assert provider.calls == 0
    assert metrics.count("convo.scenario.title", "vi", "override") == 1


@pytest.mark.asyncio
async def test_override_with_stale_version_falls_through() -> None:
    # Admin override authored against v1 must NOT serve when v2 is
    # requested — the canonical English source has been edited under
    # the admin and their translation is now reviewed against stale text.
    overrides = MapOverrideStore({
        "convo.scenario.title|s1|v1|vi": "Cốc cà phê v1-era",
    })
    seam, provider, metrics, _, _ = _make_seam(overrides=overrides)
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v2", source_text="Order a coffee"),
        target_locale="vi",
    )
    assert got == "Gọi một ly cà phê"
    assert provider.calls == 1
    assert metrics.count("convo.scenario.title", "vi", "override") == 0


# ──────────────────────── cache hit / miss / SWR ────────────────────────


@pytest.mark.asyncio
async def test_first_call_misses_then_cache_hits() -> None:
    cache = FakeCache()
    seam, provider, metrics, _, _ = _make_seam(cache=cache)
    ref = SourceRef(namespace="convo.scenario.title", source_id="s1",
                    source_version="v1", source_text="Order a coffee")

    first = await seam.translate(ref, target_locale="vi")
    assert first == "Gọi một ly cà phê"
    assert provider.calls == 1

    second = await seam.translate(ref, target_locale="vi")
    assert second == "Gọi một ly cà phê"
    assert provider.calls == 1  # cache hit, no provider call
    assert metrics.count("convo.scenario.title", "vi", "provider_call") == 1
    assert metrics.count("convo.scenario.title", "vi", "cache_hit") == 1


@pytest.mark.asyncio
async def test_stale_while_revalidate() -> None:
    cache = FakeCache()
    seam, provider, metrics, _, _ = _make_seam(cache=cache)
    ref = SourceRef(namespace="convo.scenario.title", source_id="s1",
                    source_version="v1", source_text="Order a coffee")

    await seam.translate(ref, target_locale="vi")
    assert provider.calls == 1

    # Advance past freshTTL (3600s) but within staleTTL window.
    cache.advance(7200.0)
    got = await seam.translate(ref, target_locale="vi")
    assert got == "Gọi một ly cà phê"
    assert metrics.count("convo.scenario.title", "vi", "cache_swr") == 1

    # Background refresh is a fire-and-forget task; give the event loop
    # a tick to run it and assert it happened.
    await asyncio.sleep(0.05)
    assert provider.calls >= 2


@pytest.mark.asyncio
async def test_cache_bust_on_source_version_change() -> None:
    cache = FakeCache()
    seam, provider, _, _, _ = _make_seam(cache=cache)

    v1 = SourceRef(namespace="convo.scenario.title", source_id="s1",
                   source_version="v1", source_text="Order a coffee")
    await seam.translate(v1, target_locale="vi")
    assert provider.calls == 1

    v2 = SourceRef(namespace="convo.scenario.title", source_id="s1",
                   source_version="v2", source_text="Order a coffee")
    await seam.translate(v2, target_locale="vi")
    assert provider.calls == 2  # different version → different cache key


# ──────────────────────── single-flight ──────────────────────────────────


@pytest.mark.asyncio
async def test_single_flight_coalesces_parallel_misses() -> None:
    seam, provider, metrics, _, _ = _make_seam()
    # Force a 100ms provider delay so sibling coroutines reliably enter
    # the seam's resolve() before the first call completes. Without this
    # the in-memory stub returns synchronously and single-flight has no
    # window in which to coalesce.
    provider.delay_seconds = 0.1
    ref = SourceRef(namespace="convo.scenario.title", source_id="s1",
                    source_version="v1", source_text="Order a coffee")

    results = await asyncio.gather(*(
        seam.translate(ref, target_locale="vi") for _ in range(20)
    ))
    assert all(r == "Gọi một ly cà phê" for r in results)
    assert provider.calls <= 3, f"single-flight failed to coalesce: {provider.calls} calls"
    assert metrics.count("convo.scenario.title", "vi", "cache_miss_share") >= 1


# ──────────────────────── provider error fallback ────────────────────────


@pytest.mark.asyncio
async def test_provider_error_falls_back_to_source() -> None:
    seam, provider, metrics, _, _ = _make_seam()
    provider.raise_on_call = True
    got = await seam.translate(
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Order a coffee"),
        target_locale="vi",
    )
    assert got == "Order a coffee"
    assert metrics.count("convo.scenario.title", "vi", "provider_error") == 1


# ──────────────────────── batch ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_translate_batch() -> None:
    # Sweep AAAAA: the seam now collapses N refs into ONE provider call
    # (sibling of Go TTTT-B which did the same on the Go side). Pre-
    # AAAAA this assertion was `provider.calls == 2` because translate_batch
    # was an asyncio.gather over per-item translate().
    seam, provider, _, _, _ = _make_seam()
    refs = [
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Order a coffee"),
        SourceRef(namespace="convo.scenario.title", source_id="s2",
                  source_version="v1", source_text="Hello"),
    ]
    got = await seam.translate_batch(refs, target_locale="vi")
    assert got == ["Gọi một ly cà phê", "Xin chào"]
    assert provider.calls == 1, (
        "Sweep AAAAA: translate_batch should issue ONE provider call "
        "regardless of N — got {} calls for {} refs".format(
            provider.calls, len(refs)
        )
    )


# ──────────────────────── source_version_from_text ───────────────────────


def test_source_version_from_text_stable() -> None:
    a = source_version_from_text("Order a coffee")
    b = source_version_from_text("Order a coffee")
    assert a == b
    c = source_version_from_text("Order a tea")
    assert a != c


def test_source_version_from_text_order_sensitive() -> None:
    a = source_version_from_text("Order a coffee", "2026-05-15T12:00:00Z")
    b = source_version_from_text("2026-05-15T12:00:00Z", "Order a coffee")
    assert a != b


# ──────────────────────── Sweep AAAAA: true batch path ──────────────────


class FakeBatchCache(FakeCache):
    """FakeCache + BatchCache protocol — exercises the fast path that
    PgxBatchOverrideStore / RedisCache use in production."""

    def __init__(self) -> None:
        super().__init__()
        # Track call counts so tests can assert ONE batch call instead
        # of N per-key calls.
        self.batch_get_calls = 0
        self.batch_set_calls = 0
        self.per_key_get_calls = 0
        self.per_key_set_calls = 0

    async def get(self, key: str):  # type: ignore[override]
        self.per_key_get_calls += 1
        return await super().get(key)

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:  # type: ignore[override]
        self.per_key_set_calls += 1
        await super().set(key, value, ttl_seconds)

    async def batch_get(self, keys):
        from kielo_shared.localization.seam import CacheEntry

        self.batch_get_calls += 1
        out: dict[str, CacheEntry] = {}
        for k in keys:
            entry = self._entries.get(k)
            if entry is not None:
                value, written_at = entry
                out[k] = CacheEntry(value=value, age_seconds=self._now - written_at)
        return out

    async def batch_set(self, entries, ttl_seconds: float) -> None:
        self.batch_set_calls += 1
        for k, v in entries.items():
            self._entries[k] = (v, self._now)


class FakeBatchOverrideStore:
    """OverrideStore + BatchOverrideStore — used to assert the batch
    path is exercised when wired."""

    def __init__(self, entries=None) -> None:
        from kielo_shared.localization.seam import MapOverrideStore

        self._inner = MapOverrideStore(entries or {})
        self.batch_lookup_calls = 0
        self.per_key_lookup_calls = 0

    async def lookup(self, namespace, source_id, source_version, target_locale):
        self.per_key_lookup_calls += 1
        return await self._inner.lookup(
            namespace, source_id, source_version, target_locale
        )

    async def batch_lookup(self, refs, target_locale):
        self.batch_lookup_calls += 1
        out: dict[str, str] = {}
        for ref in refs:
            hit = await self._inner.lookup(
                ref.namespace, ref.source_id, ref.source_version, target_locale
            )
            if hit:
                from kielo_shared.localization.seam import override_batch_key

                out[
                    override_batch_key(
                        ref.namespace, ref.source_id, ref.source_version
                    )
                ] = hit
        return out


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_records_one_per_phase_budget() -> None:
    """Sweep AAAAA central invariant: a batch of N refs records
    Refs:N Overrides:1 CacheGets:1 Providers:1 — matching the Go
    seam.go:184-273 post-TTTT-B shape that YYYY budget headers
    expose on the wire."""
    from kielo_shared.localization.budget import (
        budget_snapshot,
        reset_budget,
        with_budget,
    )

    seam, provider, _, _, _ = _make_seam()
    refs = [
        SourceRef(namespace="convo.scenario.title", source_id=f"s{i}",
                  source_version="v1", source_text=text)
        for i, text in enumerate(["Order a coffee", "Hello", "Order a coffee"])
    ]
    # Note: the StubProvider only knows 2 phrases, so the 3rd ref will
    # fall back to source. That's fine — we're testing budget counts
    # not translation quality.
    token = with_budget()
    try:
        _ = await seam.translate_batch(refs, target_locale="vi")
        snap = budget_snapshot()
    finally:
        reset_budget(token)

    assert snap.refs_resolved == 3, (
        f"REF_RESOLVED should record N for the whole batch (got {snap.refs_resolved})"
    )
    assert snap.override_lookups == 1, (
        f"OVERRIDE_LOOKUP should record exactly 1 regardless of N "
        f"(got {snap.override_lookups})"
    )
    assert snap.cache_gets == 1, (
        f"CACHE_GET should record exactly 1 regardless of N "
        f"(got {snap.cache_gets})"
    )
    assert snap.provider_calls == 1, (
        f"PROVIDER_CALL should record exactly 1 regardless of N "
        f"(got {snap.provider_calls})"
    )
    # And the actual provider got exactly one batch call.
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_empty_records_no_budget() -> None:
    from kielo_shared.localization.budget import (
        budget_snapshot,
        reset_budget,
        with_budget,
    )

    seam, provider, _, _, _ = _make_seam()
    token = with_budget()
    try:
        result = await seam.translate_batch([], target_locale="vi")
        snap = budget_snapshot()
    finally:
        reset_budget(token)
    assert result == []
    assert snap.refs_resolved == 0
    assert snap.override_lookups == 0
    assert snap.cache_gets == 0
    assert snap.provider_calls == 0
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_passthrough_refs_skip_phases() -> None:
    """English-target refs and empty-source refs short-circuit before
    phase 1 — the seam records REF_RESOLVED but skips overrides/cache/
    provider for those refs."""
    from kielo_shared.localization.budget import (
        budget_snapshot,
        reset_budget,
        with_budget,
    )

    seam, provider, _, _, _ = _make_seam()
    refs = [
        SourceRef(namespace="ns", source_id="s1", source_version="v1",
                  source_text=""),  # empty source → passthrough
        SourceRef(namespace="ns", source_id="s2", source_version="v1",
                  source_text="Hello"),
    ]
    token = with_budget()
    try:
        result = await seam.translate_batch(refs, target_locale="en")
        snap = budget_snapshot()
    finally:
        reset_budget(token)
    # target=en short-circuits BOTH refs to passthrough.
    assert result == ["", "Hello"]
    assert snap.refs_resolved == 2  # whole batch counted
    # No phase 1-3 work because every ref short-circuited.
    assert snap.override_lookups == 0
    assert snap.cache_gets == 0
    assert snap.provider_calls == 0
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_override_hit_skips_cache_for_that_ref() -> None:
    """Override hits remove refs from the cache/provider pipeline.
    Cache/provider still record 1 for the remaining residue."""
    overrides = FakeBatchOverrideStore(
        {"ns|s1|v1|vi": "Admin Vietnamese title"}
    )
    seam, provider, _, _, _ = _make_seam(overrides=overrides)
    refs = [
        SourceRef(namespace="ns", source_id="s1", source_version="v1",
                  source_text="Order a coffee"),  # override hit
        SourceRef(namespace="ns", source_id="s2", source_version="v1",
                  source_text="Hello"),  # falls through to provider
    ]
    result = await seam.translate_batch(refs, target_locale="vi")
    assert result == ["Admin Vietnamese title", "Xin chào"]
    # Override hit went through batch path — one batch_lookup call.
    assert overrides.batch_lookup_calls == 1
    assert overrides.per_key_lookup_calls == 0
    # Provider only saw the remaining ref — but still one batch call.
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_with_batch_cache_uses_fast_path() -> None:
    """When the cache satisfies BatchCache protocol, seam should call
    batch_get instead of per-key get."""
    cache = FakeBatchCache()
    seam, provider, _, _, _ = _make_seam(cache=cache)
    refs = [
        SourceRef(namespace="ns", source_id=f"s{i}", source_version="v1",
                  source_text=t)
        for i, t in enumerate(["Order a coffee", "Hello"])
    ]
    await seam.translate_batch(refs, target_locale="vi")

    # First call: cache miss → 1 batch_get + 1 provider + 1 batch_set
    assert cache.batch_get_calls == 1
    assert cache.per_key_get_calls == 0
    assert cache.batch_set_calls == 1
    assert cache.per_key_set_calls == 0
    assert provider.calls == 1

    # Second call: cache hit → 1 batch_get + 0 provider + 0 batch_set
    await seam.translate_batch(refs, target_locale="vi")
    assert cache.batch_get_calls == 2
    assert cache.batch_set_calls == 1  # unchanged
    assert provider.calls == 1  # unchanged — all hits


@pytest.mark.asyncio
async def test_aaaaa_translate_batch_fallback_when_cache_lacks_batch_protocol() -> None:
    """Existing FakeCache (no BatchCache protocol) must still work
    via per-key fallback. Same shape pre-AAAAA seam used."""
    cache = FakeCache()
    seam, provider, _, _, _ = _make_seam(cache=cache)
    refs = [
        SourceRef(namespace="ns", source_id=f"s{i}", source_version="v1",
                  source_text=t)
        for i, t in enumerate(["Order a coffee", "Hello"])
    ]
    result = await seam.translate_batch(refs, target_locale="vi")
    assert result == ["Gọi một ly cà phê", "Xin chào"]
    # Even with per-key fallback, provider still gets ONE batch call
    # (the per-key fallback only applies to cache, not the provider
    # phase that happens after).
    assert provider.calls == 1
