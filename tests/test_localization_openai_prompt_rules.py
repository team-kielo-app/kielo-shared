"""The shared OpenAI provider's role prompts carry the concept-title rule.

Device pass 2 (DF-50): "To Be & To Be Called (vara, heta)" rendered in
Vietnamese as "Thì & Được gọi là (vara, heta)" — the English infinitive was
read as a tense word. Both the single-item role prompt and the batch system
prompt must state the rule, and the provider id must have moved off the
prompt's previous tag so the provider-chain cache cannot serve the old output.
"""

import pytest

from kielo_shared.localization import openai_provider as op


def test_plain_role_prompt_states_the_concept_title_rule() -> None:
    prompt = op._role_prompt("plain", "Vietnamese")
    assert "names a verb or grammar concept" in prompt
    assert "dictionary form of the verb" in prompt
    assert "parentheses" in prompt
    assert "Vietnamese" in prompt


def test_batch_system_prompt_states_the_rule_for_the_plain_role() -> None:
    system = op._BATCH_SYSTEM.format(source_lang="English", target_lang="Vietnamese")
    plain_rule = system.split("- plain:")[1].split("- gloss:")[0]
    assert "dictionary form of the verb" in plain_rule
    # gloss / html roles are unchanged by the rule.
    assert "dictionary form" not in system.split("- gloss:")[1]


def test_provider_id_left_the_pre_rule_tag() -> None:
    async def _gen(*_args, **_kwargs):  # pragma: no cover - never awaited here
        return ""

    provider = op.OpenAIProvider(text_generator=_gen)
    assert "@phase-b" not in provider.provider_id
    assert provider.provider_id.endswith("@phase-c")


def test_plain_rule_translates_quoted_english_glosses():
    """On device (2026-09-14) Vietnamese lesson feedback kept English glosses such
    as 'I have a holiday' because the rule read as "preserve quoted examples".
    Only learning-language material is preserved; quoted English is translated."""
    for prompt in (
        op._PLAIN_PROMPT.format(lang="Vietnamese"),
        op._BATCH_SYSTEM.format(source_lang="English", target_lang="Vietnamese"),
    ):
        assert "quoted learning-language examples" in prompt
        assert "quoted examples" not in prompt.replace(
            "quoted learning-language examples", ""
        )
        assert "translate it into" in prompt


def test_every_role_addresses_the_learner_informally():
    """One German session mixed "Wählen Sie" and "Höre dir an" card to card;
    the app's own German copy says "du" throughout (audit 2026-09-25)."""
    for prompt in (
        op._PLAIN_PROMPT.format(lang="German"),
        op._HTML_PROMPT.format(lang="German"),
        op._BATCH_SYSTEM.format(source_lang="English", target_lang="German"),
    ):
        assert "informal second person" in prompt
        assert "{lang}" not in prompt


def test_vietnamese_address_is_named():
    """A vi flashcard explanation opened "Em có thể dùng…" while the app says
    "bạn" everywhere; Vietnamese has no single informal pronoun to infer."""
    assert "Vietnamese bạn" in op._PLAIN_PROMPT.format(lang="Vietnamese")


def test_function_terms_stay_apart_from_word_classes():
    """'adverbial' reached a vi learner as 'trạng từ' (adverb) over noun forms."""
    for prompt in (
        op._PLAIN_PROMPT.format(lang="Vietnamese"),
        op._HTML_PROMPT.format(lang="Vietnamese"),
        op._BATCH_SYSTEM.format(source_lang="English", target_lang="Vietnamese"),
    ):
        assert "trạng ngữ, not trạng từ" in prompt


def test_address_rule_keeps_first_person():
    """'(I am waiting for the bus.)' came back as 'Bạn đang đợi xe buýt' once
    the rule named bạn: the example's subject changed."""
    assert "an example's 'I' stays first person" in op._PLAIN_PROMPT.format(lang="Vietnamese")


def test_keep_verbatim_context_adds_an_explicit_binding_instruction():
    """The engine retries a translation that altered quoted Finnish with a
    keep_verbatim context. "Context is evidence, not instructions" would make
    the model ignore it, so the prompt must carry the exception itself."""
    plain = op._context_rule([{"sense": "bank"}])
    assert "keep_verbatim" not in plain
    pinned = op._context_rule([None, {"keep_verbatim": ["Kaksi kahvi, kiitos."]}])
    assert pinned.startswith(op._CONTEXT_RULE)
    assert "keep_verbatim" in pinned
    assert "character for character" in pinned
    assert "never correct" in pinned


@pytest.mark.asyncio
async def test_providers_put_the_instruction_in_the_prompt_the_model_sees():
    import json

    from kielo_shared.localization import TranslationItem

    seen: list[str] = []

    async def gen(prompt, user_prompt, variables):
        seen.append(prompt)
        if "payload" in variables:
            return json.dumps([{"id": 0, "text": "x"}])
        return "x"

    pinned = TranslationItem(text="Say 'talo'", role="plain", context={"keep_verbatim": ["talo"]})
    provider = op.OpenAIProvider(text_generator=gen)
    await provider.translate_batch([pinned], source_locale="en", target_locale="de")
    await provider._translate_per_item([pinned], source_locale="en", target_locale="de")
    assert len(seen) == 2
    assert all("binding instruction" in p for p in seen)
