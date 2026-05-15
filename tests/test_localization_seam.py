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
    TranslationRole,
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
    seam, provider, _, _, _ = _make_seam()
    refs = [
        SourceRef(namespace="convo.scenario.title", source_id="s1",
                  source_version="v1", source_text="Order a coffee"),
        SourceRef(namespace="convo.scenario.title", source_id="s2",
                  source_version="v1", source_text="Hello"),
    ]
    got = await seam.translate_batch(refs, target_locale="vi")
    assert got == ["Gọi một ly cà phê", "Xin chào"]
    assert provider.calls == 2


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
