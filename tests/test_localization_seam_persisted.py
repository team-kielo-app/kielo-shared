"""Persisted-translation read tier of `kielo_shared.localization.seam`.

override -> cache -> persisted machine row -> provider. Mirrors
`localization/seam_persisted_test.go`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from kielo_shared.localization.registry import LocalizationRegistry
from kielo_shared.localization.seam import (
    CountingMetrics,
    MapOverrideStore,
    MapPersister,
    Seam,
    SeamConfig,
    SourceRef,
    override_batch_key,
)
from kielo_shared.localization.types import TranslationItem, TranslationResult

PROSE = "Practice reading short Finnish sentences every day"


class Provider:
    provider_id = "stub-vi"

    def __init__(self, answers: dict[str, str] | None = None) -> None:
        self.answers = answers or {}
        self.calls = 0

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        self.calls += 1
        return [
            TranslationResult(
                text=self.answers.get(i.text, "vi:" + i.text), provider=self.provider_id
            )
            for i in items
        ]


class Cache:
    def __init__(self) -> None:
        self.entries: dict[str, tuple[str, float]] = {}
        self.now = 0.0

    async def get(self, key: str) -> tuple[str | None, float | None]:
        hit = self.entries.get(key)
        return (None, None) if hit is None else (hit[0], self.now - hit[1])

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        self.entries[key] = (value, self.now)


class Rows:
    def __init__(self, rows: dict[str, str]) -> None:
        self.rows = rows
        self.lookups = 0
        self.batches = 0

    async def lookup(self, ns: str, sid: str, ver: str, target: str) -> str | None:
        self.lookups += 1
        return self.rows.get(override_batch_key(ns, sid, ver))


class BatchRows(Rows):
    async def batch_lookup(self, refs: list[Any], target: str) -> dict[str, str]:
        self.batches += 1
        out = {}
        for r in refs:
            k = override_batch_key(r.namespace, r.source_id, r.source_version)
            if k in self.rows:
                out[k] = self.rows[k]
        return out


def _ref(sid: str = "a", text: str = "Hello", ver: str = "v1") -> SourceRef:
    return SourceRef(
        namespace="ns", source_id=sid, source_version=ver, source_text=text
    )


def _seam(
    *,
    persisted: Any = None,
    provider: Provider | None = None,
    overrides: Any = None,
    cache: Cache | None = None,
    persister: MapPersister | None = None,
) -> tuple[Seam, Provider, CountingMetrics, Cache, MapPersister]:
    provider = provider or Provider()
    registry = LocalizationRegistry()
    registry.register(provider.provider_id, provider)
    registry.route("en", "vi", provider.provider_id)
    cache = cache or Cache()
    metrics = CountingMetrics()
    persister = persister or MapPersister()
    seam = Seam(
        registry,
        cache=cache,
        overrides=overrides,
        metrics=metrics,
        persister=persister,
        persisted=persisted,
        config=SeamConfig(fresh_ttl_seconds=3600.0, stale_ttl_seconds=86400.0),
    )
    return seam, provider, metrics, cache, persister


def _key(sid: str = "a", ver: str = "v1") -> str:
    return override_batch_key("ns", sid, ver)


@pytest.mark.asyncio
async def test_persisted_row_served_without_provider() -> None:
    seam, provider, metrics, cache, persister = _seam(
        persisted=Rows({_key(): "Xin chao"})
    )
    assert await seam.translate(_ref(), "vi") == "Xin chao"
    assert provider.calls == 0
    assert persister.calls == []
    assert metrics.count("ns", "vi", "persisted") == 1
    assert await seam.translate(_ref(), "vi") == "Xin chao"
    assert metrics.count("ns", "vi", "cache_hit") == 1


@pytest.mark.asyncio
async def test_absent_tier_keeps_provider_path() -> None:
    seam, provider, metrics, _, persister = _seam()
    assert await seam.translate(_ref(), "vi") == "vi:Hello"
    assert provider.calls == 1
    assert len(persister.calls) == 1
    assert metrics.count("ns", "vi", "provider_call") == 1


@pytest.mark.asyncio
async def test_identical_prose_row_is_ignored_and_rewritten() -> None:
    ref = _ref(text=PROSE)
    seam, provider, metrics, _, persister = _seam(persisted=Rows({_key(): PROSE}))
    assert await seam.translate(ref, "vi") == "vi:" + PROSE
    assert provider.calls == 1
    assert metrics.count("ns", "vi", "provider_call") == 1
    assert persister.calls[0][4] == "vi:" + PROSE


@pytest.mark.asyncio
async def test_identical_short_row_is_served() -> None:
    seam, provider, _, _, _ = _seam(persisted=Rows({_key(): "Kielo"}))
    assert await seam.translate(_ref(text="Kielo"), "vi") == "Kielo"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_override_beats_persisted() -> None:
    persisted = Rows({_key(): "machine"})
    seam, provider, metrics, _, _ = _seam(
        persisted=persisted, overrides=MapOverrideStore({"ns|a|v1|vi": "admin"})
    )
    assert await seam.translate(_ref(), "vi") == "admin"
    assert persisted.lookups == 0
    assert metrics.count("ns", "vi", "override") == 1


@pytest.mark.asyncio
async def test_swr_refresh_uses_row_not_provider() -> None:
    cache = Cache()
    seam, provider, metrics, _, persister = _seam(
        persisted=Rows({_key(): "row"}), cache=cache
    )
    ref = _ref()
    cache.entries[seam._cache_key(ref, "vi")] = ("old", 0.0)
    cache.now = 7200.0
    assert await seam.translate(ref, "vi") == "old"
    assert metrics.count("ns", "vi", "cache_swr") == 1
    await asyncio.sleep(0.05)
    assert provider.calls == 0
    assert persister.calls == []
    assert cache.entries[seam._cache_key(ref, "vi")][0] == "row"


@pytest.mark.asyncio
async def test_swr_with_stand_in_row_calls_provider() -> None:
    cache = Cache()
    seam, provider, _, _, _ = _seam(persisted=Rows({_key(): PROSE}), cache=cache)
    ref = _ref(text=PROSE)
    cache.entries[seam._cache_key(ref, "vi")] = ("old", 0.0)
    cache.now = 7200.0
    await seam.translate(ref, "vi")
    await asyncio.sleep(0.05)
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_persisted_lookup_error_falls_through_to_provider() -> None:
    class Boom:
        async def lookup(self, *a: Any) -> str | None:
            raise RuntimeError("db down")

    seam, provider, _, _, _ = _seam(persisted=Boom())
    assert await seam.translate(_ref(), "vi") == "vi:Hello"
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_batch_serves_rows_in_one_query_and_calls_provider_for_rest() -> None:
    rows = BatchRows({_key("a"): "A-row", _key("b"): PROSE})
    seam, provider, metrics, cache, persister = _seam(persisted=rows)
    refs = [_ref("a", "Hello"), _ref("b", PROSE), _ref("c", "Bye")]
    out = await seam.translate_batch(refs, "vi")
    assert out == ["A-row", "vi:" + PROSE, "vi:Bye"]
    assert rows.batches == 1
    assert provider.calls == 1
    assert metrics.count("ns", "vi", "persisted") == 1
    assert {c[1] for c in persister.calls} == {"b", "c"}
    assert cache.entries[seam._cache_key(refs[0], "vi")][0] == "A-row"


@pytest.mark.asyncio
async def test_batch_all_persisted_skips_provider() -> None:
    rows = BatchRows({_key("a"): "A-row", _key("b"): "B-row"})
    seam, provider, _, _, persister = _seam(persisted=rows)
    out = await seam.translate_batch([_ref("a"), _ref("b", "Bye")], "vi")
    assert out == ["A-row", "B-row"]
    assert provider.calls == 0
    assert persister.calls == []


@pytest.mark.asyncio
async def test_batch_without_batch_protocol_falls_back_per_ref() -> None:
    rows = Rows({_key("a"): "A-row"})
    seam, provider, _, _, _ = _seam(persisted=rows)
    out = await seam.translate_batch([_ref("a"), _ref("c", "Bye")], "vi")
    assert out == ["A-row", "vi:Bye"]
    assert rows.lookups == 2


@pytest.mark.asyncio
async def test_unchanged_provider_value_is_not_persisted_again() -> None:
    rows = Rows({_key(): PROSE})
    provider = Provider({PROSE: PROSE})
    seam, _, _, _, persister = _seam(persisted=rows, provider=provider)
    assert await seam.translate(_ref(text=PROSE), "vi") == PROSE
    assert provider.calls == 1
    assert persister.calls == []


@pytest.mark.asyncio
async def test_pgx_persisted_store_filters_machine_status() -> None:
    from kielo_shared.localization.override_pgx import PgxPersistedStore
    from kielo_shared.localization.seam import OverrideRef

    seen: list[str] = []

    class Pool:
        async def fetchval(self, query: str, *args: Any) -> Any:
            seen.append(query)
            return "row"

        async def fetch(self, query: str, *args: Any) -> list[Any]:
            seen.append(query)
            return [
                {
                    "resource_type": "ns",
                    "resource_id": "a",
                    "source_version": "v1",
                    "translated_text": "row",
                    "status": "machine",
                }
            ]

    store = PgxPersistedStore(Pool())
    assert await store.lookup("ns", "a", "v1", "vi") == "row"
    assert await store.batch_lookup([OverrideRef("ns", "a", "v1")], "vi") == {
        _key(): "row"
    }
    assert all("= 'machine'" in q and "'approved'" not in q for q in seen)
