from kielo_shared.localization.openai_provider import _BATCH_SYSTEM, batch_system_prompt


def _full() -> str:
    return _BATCH_SYSTEM.format(source_lang="English", target_lang="German")


def test_a_gloss_only_batch_leaves_out_the_prose_rules():
    prompt = batch_system_prompt(["gloss", "gloss"], "English", "German")
    assert "- gloss:" in prompt
    assert "- plain:" not in prompt
    assert "- html:" not in prompt
    assert len(prompt) < len(_full()) / 2


def test_a_mixed_batch_gets_each_present_role_and_matches_the_full_prompt():
    assert batch_system_prompt(["plain", "gloss", "html"], "English", "German") == _full()


def test_an_unknown_or_missing_role_falls_back_to_the_plain_rules():
    assert "- plain:" in batch_system_prompt(["title"], "English", "German")
    assert "- plain:" in batch_system_prompt([], "English", "German")
