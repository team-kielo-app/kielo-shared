from kielo_shared.localization.openai_provider import restore_learning_words


def test_a_learning_word_read_as_target_language_is_put_back() -> None:
    assert (
        restore_learning_words(
            "Mä/Sä vs. Minä/Sinä: Reading the Room",
            "Mã/Sä so với Minä/Sinä: Đọc tình huống",
        )
        == "Mä/Sä so với Minä/Sinä: Đọc tình huống"
    )


def test_translations_that_kept_the_words_are_untouched() -> None:
    source = "The word 'mä' is colloquial for 'minä'."
    translated = "Từ 'mä' là cách nói thân mật của 'minä'."
    assert restore_learning_words(source, translated) == translated


def test_target_language_words_that_only_share_letters_stay() -> None:
    assert restore_learning_words("Say 'kiitos'.", "Hãy nói 'kiitos'.") == "Hãy nói 'kiitos'."
    assert restore_learning_words("Hyvää päivää", "Chúc một ngày tốt lành") == "Chúc một ngày tốt lành"



def test_the_gemini_provider_restores_learning_words() -> None:
    import asyncio
    import json

    from kielo_shared.localization.gemini_provider import GeminiProvider
    from kielo_shared.localization.types import TranslationItem

    async def mangling_model(system: str, user: str, extra: dict | None) -> str:
        items = json.loads((extra or {})["payload"])
        return json.dumps(
            [{"id": item["id"], "text": "Mã/Sä so với Minä/Sinä"} for item in items]
        )

    provider = GeminiProvider(mangling_model)
    results = asyncio.run(
        provider.translate_batch(
            [TranslationItem(text="Mä/Sä vs. Minä/Sinä")],
            source_locale="en",
            target_locale="vi",
        )
    )
    assert results[0].text == "Mä/Sä so với Minä/Sinä"


def test_english_names_of_finnish_cases_become_the_finnish_names() -> None:
    from kielo_shared.localization.openai_provider import name_finnish_cases

    assert (
        name_finnish_cases("Bạn phải dùng cách illative (vào trong) và cách Allative.")
        == "Bạn phải dùng cách illatiivi (vào trong) và cách Allatiivi."
    )
    assert name_finnish_cases("đuôi cách essivi -na/-nä") == "đuôi cách essiivi -na/-nä"


def test_case_renaming_leaves_other_words_and_spellings_alone() -> None:
    from kielo_shared.localization.openai_provider import name_finnish_cases

    for text in ("Der Illativ zeigt eine Richtung.", "cách bộ phận", "elatiivi", "relative clause", ""):
        assert name_finnish_cases(text) == text
