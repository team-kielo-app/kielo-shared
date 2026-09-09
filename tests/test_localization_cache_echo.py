from __future__ import annotations

import pytest

from kielo_shared.localization.cache import RedisCacheDecorator, _is_source_echo
from kielo_shared.localization.types import TranslationItem, TranslationResult


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        del ex
        self.values[key] = value


class _Provider:
    provider_id = "test"

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        del source_locale, target_locale, idempotency_key
        self.calls += 1
        return [
            TranslationResult(text=self.text, provider=self.provider_id) for _ in items
        ]


@pytest.mark.asyncio
async def test_cross_locale_source_echo_is_not_cached() -> None:
    redis = _Redis()
    provider = _Provider("I have been home all day.")
    cached = RedisCacheDecorator(provider, redis)
    item = TranslationItem(text="I have been home all day.", role="plain")

    first = await cached.translate_batch([item], source_locale="en", target_locale="ru")
    second = await cached.translate_batch(
        [item], source_locale="en", target_locale="ru"
    )

    assert first[0].text == item.text
    assert second[0].text == item.text
    assert provider.calls == 2
    assert redis.values == {}


@pytest.mark.asyncio
async def test_real_cross_locale_translation_is_cached() -> None:
    redis = _Redis()
    provider = _Provider("Я был дома весь день.")
    cached = RedisCacheDecorator(provider, redis)
    item = TranslationItem(text="I have been home all day.", role="plain")

    await cached.translate_batch([item], source_locale="en", target_locale="ru")
    result = await cached.translate_batch(
        [item], source_locale="en", target_locale="ru"
    )

    assert result[0].text == "Я был дома весь день."
    assert result[0].cached is True
    assert provider.calls == 1


# --- the false positives a bare "output == input" test would cause ----------
#
# Measured against prod's curated corpus 2026-09-09: 158 distinct strings are
# LEGITIMATELY identical to their English source in every one of the 18 UI
# languages. Refusing to cache these would mean a provider call on every
# request for the app's most common strings, plus a WARNING per occurrence.
#
# The four Finnish greetings are the sharpest case: they are the CONTENT the
# app teaches, so identical is the only correct answer.


@pytest.mark.parametrize(
    "text",
    [
        "Discord",
        "YouTube",
        "App Store",
        "Kielo Plus",
        "KieloTV",
        "Juttukaveri",
        "Hei",
        "Moikka",
        "Moro",
        "Terve",
        "{{xp}} XP",
        "CEFR {{level}}",
        "{{completed}}/{{total}} \u00b7 XP {{xp}} \u00b7 \U0001f525 {{days}}",
        "Paikallissijat (-ssa, -sta, -Vn)",
        "KPT-astevaihtelu (Vahva/Heikko)",
        "x",
    ],
)
def test_legitimately_identical_strings_are_not_treated_as_echoes(text: str) -> None:
    assert _is_source_echo(text, text, "en", "ja") is False, (
        f"{text!r} is correctly identical across locales — flagging it costs a "
        "permanent cache miss on a hot string"
    )


@pytest.mark.parametrize(
    "text",
    [
        "I have been home all day.",
        "Use the Finnish word for 'father' in this sentence.",
        "The structure follows this logic: the partitive marks an incomplete action.",
        "Ermin has them ready. About 5 minutes.",
    ],
)
def test_echoed_prose_is_detected(text: str) -> None:
    assert _is_source_echo(text, text, "en", "ru") is True


def test_same_language_identical_output_is_never_an_echo() -> None:
    # en -> en-GB, or a resolver that hands back the same base language: an
    # identical result is the expected one, however long the text.
    long_text = "The structure follows this logic: the partitive marks an action."
    assert _is_source_echo(long_text, long_text, "en", "en-GB") is False
    assert _is_source_echo(long_text, long_text, "en", "en") is False


def test_a_real_translation_is_never_an_echo() -> None:
    assert (
        _is_source_echo(
            "I have been home all day.", "Olin kotona koko paivan.", "en", "fi"
        )
        is False
    )


@pytest.mark.asyncio
async def test_legitimate_identical_string_is_still_cached() -> None:
    # End-to-end through the decorator, not just the predicate: a brand name
    # must reach Redis so the second call is a hit.
    redis = _Redis()
    provider = _Provider("YouTube")
    cached = RedisCacheDecorator(provider, redis)
    item = TranslationItem(text="YouTube", role="plain")

    await cached.translate_batch([item], source_locale="en", target_locale="ja")
    result = await cached.translate_batch(
        [item], source_locale="en", target_locale="ja"
    )

    assert result[0].text == "YouTube"
    assert result[0].cached is True
    assert provider.calls == 1, "a legitimately identical string must be cached"
