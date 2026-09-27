"""A translated title keeps the target language's capitalisation.

English Title Case was copied into Vietnamese study-guide titles ("Cảm nhận và
Vẻ ngoài của Sự vật: Cách Tách biệt với các Động từ Chỉ tri giác", 2026-09-27).
The rule rides in both prompts; the plain one formats with `lang` only, so the
rule must not need `target_lang` there.
"""

from kielo_shared.localization.openai_provider import _BATCH_SYSTEM, _PLAIN_PROMPT


def test_the_plain_prompt_carries_the_casing_rule() -> None:
    prompt = _PLAIN_PROMPT.format(lang="Vietnamese")
    assert "not in English Title Case" in prompt
    assert "the way Vietnamese capitalises" in prompt


def test_the_batch_prompt_carries_the_casing_rule() -> None:
    prompt = _BATCH_SYSTEM.format(source_lang="English", target_lang="Vietnamese")
    assert "the way Vietnamese capitalises" in prompt


def test_both_prompts_forbid_english_left_in_a_translated_title() -> None:
    # "Làm chủ Finnish Passive Voice" reached vi learners: the concept name
    # was treated as a name to keep (2026-09-27).
    plain = _PLAIN_PROMPT.format(lang="Vietnamese")
    batch = _BATCH_SYSTEM.format(source_lang="English", target_lang="Vietnamese")
    for prompt in (plain, batch):
        assert "no English word stays in a translated title" in prompt
