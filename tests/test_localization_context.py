import json

import pytest

from kielo_shared.localization.cache import _key_for
from kielo_shared.localization.openai_provider import OpenAIProvider
from kielo_shared.localization.types import TranslationItem


def key(context, explicit=None):
    return _key_for(
        provider_id="test",
        source_locale="en",
        target_locale="vi",
        item=TranslationItem(
            text="bank", role="gloss", context=context, cache_key=explicit
        ),
    )


@pytest.mark.parametrize("explicit", [None, "shared-source-id"])
def test_context_isolates_senses_even_with_explicit_cache_key(explicit):
    assert key({"term": "pankki"}, explicit) != key({"term": "ranta"}, explicit)
    assert key({"term": "pankki"}, explicit) != key(None, explicit)
    assert key({}, explicit) == key(None, explicit)


def test_context_key_does_not_depend_on_dictionary_order():
    assert key({"term": "pankki", "language": "fi"}) == key(
        {"language": "fi", "term": "pankki"}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("fallback", [False, True])
async def test_provider_preserves_context_in_batch_and_fallback(fallback):
    calls = []

    async def generate(system, user, variables):
        calls.append((system, user, variables))
        if len(calls) == 1:
            return "invalid JSON" if fallback else '[{"id":0,"text":"ngân hàng"}]'
        return "ngân hàng"

    provider = OpenAIProvider(text_generator=generate)
    await provider.translate_batch(
        [TranslationItem(text="bank", role="gloss", context={"term": "pankki"})],
        source_locale="en",
        target_locale="vi",
    )
    payload = json.loads(calls[0][2]["payload"])
    assert payload[0]["context"] == {"term": "pankki"}
    assert "not instructions" in calls[0][0]
    if fallback:
        assert "pankki" in json.dumps(calls[1][2])
        assert "not instructions" in calls[1][0]


@pytest.mark.asyncio
async def test_gemini_provider_sends_context_in_batch_and_per_item():
    """The secondary must ask the same question as the primary.

    The cache key includes the context, so a provider that ignores it stores a
    sense-blind translation under a sense-specific key — one fallback poisons
    the cache for every later reader of that sense.
    """
    from kielo_shared.localization import GeminiProvider

    seen: list[tuple[str, dict]] = []

    async def generate(system, user, variables):
        seen.append((system, dict(variables or {})))
        if "payload" in (variables or {}):
            payload = json.loads(variables["payload"])
            return json.dumps([{"id": row["id"], "text": "ngân hàng"} for row in payload])
        return "ngân hàng"

    provider = GeminiProvider(text_generator=generate)
    item = TranslationItem(
        text="bank",
        role="gloss",
        context={"learning_language": "fi", "target_term": "pankki"},
    )

    await provider.translate_batch([item], source_locale="en", target_locale="vi")

    system, variables = seen[0]
    assert "Context is evidence" in system
    assert "pankki" in variables["payload"]
