"""Translation provenance: `TranslationResult.status` and what each layer does
with a result that is the source standing in for an answer.

Before `status`, `provider == "passthrough"` meant six different things and the
seam never read it, so an outage cached the English source for the whole TTL and
persisted it as a machine translation. Each test names the claim it pins.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kielo_shared.localization.cache import RedisCacheDecorator
from kielo_shared.localization.decorators import CorrelationDecorator
from kielo_shared.localization.fallback import FallbackDecorator
from kielo_shared.localization.gemini_provider import GeminiProvider
from kielo_shared.localization.openai_provider import OpenAIProvider
from kielo_shared.localization.registry import LocalizationRegistry
from kielo_shared.localization.routing import RoutingDecorator
from kielo_shared.localization.seam import (
    CountingMetrics,
    MapPersister,
    Seam,
    SeamConfig,
    SourceRef,
)
from kielo_shared.localization.types import (
    TranslationItem,
    TranslationResult,
    is_prose,
    is_source_echo,
)

PROSE = "I have been home all day."
TTL = 7 * 24 * 3600


def _status(result: TranslationResult) -> str:
    return getattr(result, "status", "<missing>")


class _Generator:
    """Scripted text generator. `replies` is consumed one per call; an
    exhausted script keeps returning its last entry. None models
    llm_service.generate_text swallowing a timeout / 429 / provider error."""

    def __init__(self, *replies: str | None) -> None:
        self.replies = list(replies)
        self.calls = 0

    async def __call__(
        self, system: str, user: str, variables: dict | None
    ) -> str | None:
        self.calls += 1
        reply = self.replies[min(self.calls, len(self.replies)) - 1]
        return reply


def _batch_reply(*texts: str) -> str:
    return json.dumps([{"id": i, "text": t} for i, t in enumerate(texts)])


def _items(*texts: str) -> list[TranslationItem]:
    return [TranslationItem(text=t) for t in texts]


async def _translate(provider: Any, *texts: str, target: str = "vi") -> list:
    return await provider.translate_batch(
        _items(*texts), source_locale="en", target_locale=target
    )


# ───────────────── claim 1: every producer says what it is ───────────────


@pytest.mark.asyncio
async def test_same_locale_target_is_marked_same_locale() -> None:
    gen = _Generator("unused")
    out = await _translate(OpenAIProvider(gen), "Hello", target="en")
    assert (out[0].provider, _status(out[0])) == ("passthrough", "same_locale")
    assert gen.calls == 0


@pytest.mark.asyncio
async def test_blank_source_is_marked_empty_source() -> None:
    gen = _Generator("unused")
    out = await _translate(OpenAIProvider(gen), "   ")
    assert _status(out[0]) == "empty_source"
    assert gen.calls == 0


@pytest.mark.asyncio
async def test_model_empty_answer_is_unavailable() -> None:
    out = await _translate(
        OpenAIProvider(_Generator(_batch_reply("")), provider_id="m"), "Hello"
    )
    assert out[0].text == "Hello"
    assert _status(out[0]) == "unavailable"


@pytest.mark.asyncio
async def test_failed_call_is_unavailable() -> None:
    out = await _translate(OpenAIProvider(_Generator(None)), "Hello", "Bye")
    assert [(r.text, _status(r)) for r in out] == [
        ("Hello", "unavailable"),
        ("Bye", "unavailable"),
    ]


@pytest.mark.asyncio
async def test_model_answering_with_the_source_is_an_echo_not_a_translation() -> None:
    out = await _translate(
        OpenAIProvider(_Generator(_batch_reply("hello  ")), provider_id="gpt-x"),
        "Hello",
    )
    assert out[0].provider == "gpt-x"
    assert out[0].text == "hello"
    assert _status(out[0]) == "echo"


@pytest.mark.asyncio
async def test_real_translation_stays_translated() -> None:
    out = await _translate(
        OpenAIProvider(_Generator(_batch_reply("Xin chào")), provider_id="gpt-x"),
        "Hello",
    )
    assert _status(out[0]) == "translated"


@pytest.mark.asyncio
async def test_mixed_batch_labels_each_slot() -> None:
    out = await _translate(
        OpenAIProvider(_Generator(_batch_reply("Xin chào")), provider_id="gpt-x"),
        "Hello",
        "  ",
    )
    assert [_status(r) for r in out] == ["translated", "empty_source"]


@pytest.mark.asyncio
async def test_routing_length_mismatch_is_unavailable() -> None:
    class Short:
        provider_id = "short"

        async def translate_batch(self, items, **_: Any):
            return [TranslationResult(text="x", provider="short")]

    out = await RoutingDecorator(Short()).translate_batch(
        _items("a", "b"), source_locale="en", target_locale="vi"
    )
    assert [_status(r) for r in out] == ["unavailable", "unavailable"]


@pytest.mark.asyncio
async def test_routing_tier_a_target_is_same_locale() -> None:
    out = await RoutingDecorator(OpenAIProvider(_Generator("x"))).translate_batch(
        _items("a"), source_locale="en", target_locale="en"
    )
    assert _status(out[0]) == "same_locale"


@pytest.mark.asyncio
async def test_cache_unfilled_slot_is_unavailable() -> None:
    class Short:
        provider_id = "short"

        async def translate_batch(self, items, **_: Any):
            return [TranslationResult(text="x", provider="short")]

    out = await RedisCacheDecorator(Short(), _Redis()).translate_batch(
        _items("a", "b"), source_locale="en", target_locale="vi"
    )
    assert out[1].text == "b"
    assert _status(out[1]) == "unavailable"


@pytest.mark.asyncio
async def test_fallback_with_every_breaker_open_is_unavailable() -> None:
    class Boom:
        provider_id = "boom"

        async def translate_batch(self, items, **_: Any):
            raise RuntimeError("down")

    chain = FallbackDecorator([Boom()], breaker_threshold=1, breaker_recovery_secs=60)
    with pytest.raises(RuntimeError):
        await _translate(chain, "Hello")
    out = await _translate(chain, "Hello")
    assert (out[0].text, _status(out[0])) == ("Hello", "unavailable")


@pytest.mark.asyncio
async def test_fallback_advances_past_a_provider_that_swallows_its_outage() -> None:
    down = OpenAIProvider(_Generator(None), provider_id="down")
    up = OpenAIProvider(_Generator(_batch_reply("Xin chào")), provider_id="up")
    out = await _translate(FallbackDecorator([down, up]), "Hello")
    assert (out[0].provider, out[0].text) == ("up", "Xin chào")


@pytest.mark.asyncio
async def test_fallback_returns_unavailable_when_every_provider_is_down() -> None:
    out = await _translate(
        FallbackDecorator([OpenAIProvider(_Generator(None))]), "Hello"
    )
    assert _status(out[0]) == "unavailable"


@pytest.mark.asyncio
async def test_correlation_decorator_keeps_status() -> None:
    out = await _translate(
        CorrelationDecorator(OpenAIProvider(_Generator(None))), "Hello"
    )
    assert _status(out[0]) == "unavailable"
    assert out[0].correlation_id


def test_legacy_passthrough_provider_reads_as_passthrough() -> None:
    legacy = TranslationResult(text="Hello", provider="passthrough")
    assert legacy.is_passthrough
    assert not TranslationResult(text="Xin chào", provider="m").is_passthrough
    assert not TranslationResult(
        text="Hello", provider="m", status="echo"
    ).is_passthrough


def test_echo_and_prose_predicates() -> None:
    assert is_source_echo("Hello world", "  hello   WORLD ")
    assert not is_source_echo("", "")
    assert is_prose(PROSE)
    for short in (
        "Discord",
        "Kielo Plus",
        "{{xp}} XP",
        "Hei",
        "Paikallissijat (-ssa, -sta, -Vn)",
    ):
        assert not is_prose(short)


# ───────────── claim 4: an outage costs one call, not N ──────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("make", [OpenAIProvider, GeminiProvider])
async def test_outage_on_the_batch_call_is_one_call(make: Any) -> None:
    gen = _Generator(None)
    out = await _translate(make(gen), *[f"text {i}" for i in range(8)])
    assert gen.calls == 1
    assert {_status(r) for r in out} == {"unavailable"}


@pytest.mark.asyncio
@pytest.mark.parametrize("make", [OpenAIProvider, GeminiProvider])
async def test_unparsable_batch_then_outage_stops_after_first_item(make: Any) -> None:
    gen = _Generator("not json", None)
    out = await _translate(make(gen), *[f"text {i}" for i in range(8)])
    assert gen.calls == 2
    assert {_status(r) for r in out} == {"unavailable"}


@pytest.mark.asyncio
@pytest.mark.parametrize("make", [OpenAIProvider, GeminiProvider])
async def test_unparsable_batch_with_healthy_backend_still_fans_out(make: Any) -> None:
    gen = _Generator("not json", "dịch")
    out = await _translate(make(gen), "one", "two", "three")
    assert gen.calls == 4
    assert [r.text for r in out] == ["dịch"] * 3
    assert {_status(r) for r in out} == {"translated"}


# ───────────── claim 2: what the provider cache keeps ────────────────────


class _Redis:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.data[key] = value
        self.ttls[key] = ex


class _Fixed:
    provider_id = "fixed"

    def __init__(self, **result: Any) -> None:
        self._result = result

    async def translate_batch(self, items, **_: Any):
        return [
            TranslationResult(text=item.text, **{"provider": "fixed", **self._result})
            for item in items
        ]


async def _cached(provider: Any, text: str, target: str = "vi") -> _Redis:
    redis = _Redis()
    await RedisCacheDecorator(provider, redis, ttl_sec=TTL).translate_batch(
        _items(text), source_locale="en", target_locale=target
    )
    return redis


@pytest.mark.asyncio
async def test_prose_echo_is_cached_only_briefly() -> None:
    redis = await _cached(_Fixed(), PROSE)
    assert list(redis.ttls.values()) == [3600]


@pytest.mark.asyncio
async def test_prose_echo_flagged_by_provider_is_cached_only_briefly() -> None:
    redis = await _cached(_Fixed(status="echo"), PROSE)
    assert list(redis.ttls.values()) == [3600]


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["YouTube", "Kielo Plus", "Hei", "{{xp}} XP"])
async def test_short_identical_answer_keeps_the_normal_ttl(text: str) -> None:
    redis = await _cached(_Fixed(), text)
    assert list(redis.ttls.values()) == [TTL]
    assert list(redis.data.values()) == [text]


@pytest.mark.asyncio
async def test_prose_echo_between_variants_of_one_language_keeps_the_normal_ttl() -> (
    None
):
    redis = _Redis()
    await RedisCacheDecorator(_Fixed(), redis, ttl_sec=TTL).translate_batch(
        _items(PROSE), source_locale="en", target_locale="en-GB"
    )
    assert list(redis.ttls.values()) == [TTL]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "marker",
    [
        {"status": "unavailable"},
        {"status": "empty_source"},
        {"status": "same_locale"},
        {"provider": "passthrough"},
    ],
)
async def test_passthroughs_are_never_cached(marker: dict) -> None:
    redis = await _cached(_Fixed(**marker), "Hello")
    assert redis.data == {}


@pytest.mark.asyncio
async def test_real_translation_is_cached_for_the_full_ttl() -> None:
    redis = await _cached(
        OpenAIProvider(_Generator(_batch_reply("Xin chào")), provider_id="m"), "Hello"
    )
    assert list(redis.data.values()) == ["Xin chào"]
    assert list(redis.ttls.values()) == [TTL]


# ───────── claim 3: the seam never caches or persists a stand-in ─────────


class _SeamCache:
    def __init__(self) -> None:
        self.entries: dict[str, str] = {}

    async def get(self, key: str) -> tuple[str | None, float | None]:
        value = self.entries.get(key)
        return (value, 0.0) if value is not None else (None, None)

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        self.entries[key] = value


def _seam(provider: Any) -> tuple[Seam, _SeamCache, MapPersister, CountingMetrics]:
    registry = LocalizationRegistry()
    registry.register(provider.provider_id, provider)
    registry.route("en", "vi", provider.provider_id)
    cache, persister, metrics = _SeamCache(), MapPersister(), CountingMetrics()
    seam = Seam(
        registry,
        cache=cache,
        metrics=metrics,
        persister=persister,
        config=SeamConfig(),
    )
    return seam, cache, persister, metrics


def _ref(i: int = 0, text: str = "Order a coffee") -> SourceRef:
    return SourceRef(
        namespace="ui", source_id=f"s{i}", source_version="v1", source_text=text
    )


@pytest.mark.asyncio
async def test_single_item_outage_is_served_but_not_cached_or_persisted() -> None:
    seam, cache, persister, metrics = _seam(OpenAIProvider(_Generator(None)))
    assert await seam.translate(_ref(), "vi") == "Order a coffee"
    assert cache.entries == {}
    assert persister.calls == []
    assert metrics.count("ui", "vi", "provider_error") == 1
    assert metrics.count("ui", "vi", "provider_call") == 0


@pytest.mark.asyncio
async def test_batch_outage_is_served_but_not_cached_or_persisted() -> None:
    seam, cache, persister, metrics = _seam(OpenAIProvider(_Generator(None)))
    got = await seam.translate_batch([_ref(0), _ref(1, "Hello")], "vi")
    assert got == ["Order a coffee", "Hello"]
    assert cache.entries == {}
    assert persister.calls == []
    assert metrics.count("ui", "vi", "provider_error") == 2


@pytest.mark.asyncio
async def test_legacy_passthrough_provider_is_not_cached_by_the_seam() -> None:
    class Legacy:
        provider_id = "legacy"

        async def translate_batch(self, items, **_: Any):
            return [
                TranslationResult(text=i.text, provider="passthrough") for i in items
            ]

    seam, cache, persister, metrics = _seam(Legacy())
    await seam.translate(_ref(), "vi")
    await seam.translate_batch([_ref(1)], "vi")
    assert cache.entries == {} and persister.calls == []
    assert metrics.count("ui", "vi", "provider_error") == 2


@pytest.mark.asyncio
async def test_seam_recovers_once_the_provider_does() -> None:
    gen = _Generator(None, _batch_reply("Gọi một ly cà phê"))
    seam, cache, persister, _ = _seam(OpenAIProvider(gen, provider_id="m"))
    assert await seam.translate(_ref(), "vi") == "Order a coffee"
    assert await seam.translate(_ref(), "vi") == "Gọi một ly cà phê"
    assert list(cache.entries.values()) == ["Gọi một ly cà phê"]
    assert [c[-1] for c in persister.calls] == ["Gọi một ly cà phê"]


@pytest.mark.asyncio
async def test_real_translation_is_still_cached_and_persisted() -> None:
    seam, cache, persister, metrics = _seam(
        OpenAIProvider(_Generator(_batch_reply("Gọi một ly cà phê")), provider_id="m")
    )
    await seam.translate_batch([_ref()], "vi")
    assert list(cache.entries.values()) == ["Gọi một ly cà phê"]
    assert len(persister.calls) == 1
    assert metrics.count("ui", "vi", "provider_call") == 1
