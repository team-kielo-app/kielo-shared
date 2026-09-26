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
