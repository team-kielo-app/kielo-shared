from kielo_shared.locale_constants import (
    LANGUAGE_ATTRIBUTE,
    TIER_A_SUPPORT_LOCALE,
    base_locale,
    language_from_attributes,
    normalize_accept_language,
    normalize_learning_language_code,
    normalize_locale_code,
    normalize_source_locale,
    support_locale_candidates,
)


def test_locale_normalizers_return_base_language_codes() -> None:
    assert normalize_locale_code("sv-SE") == "sv"
    assert normalize_learning_language_code(" fi-FI ") == "fi"
    assert normalize_source_locale("en-US") == "en"
    assert normalize_accept_language("pt-BR,pt;q=0.9") == "pt"
    assert base_locale("zh_CN") == "zh"


def test_support_locale_candidates_are_base_only() -> None:
    assert support_locale_candidates("vi-VN") == ["vi", TIER_A_SUPPORT_LOCALE]
    assert support_locale_candidates("en-US") == [TIER_A_SUPPORT_LOCALE]


def test_language_from_attributes_normalizes_to_base_code() -> None:
    # Region-tagged publisher attributes collapse to base codes.
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: "sv-SE"}) == "sv"
    # Vietnamese alias normalizes to canonical 'vi'.
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: "vn"}) == "vi"
    # Already-canonical codes pass through unchanged.
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: "fi"}) == "fi"


def test_language_from_attributes_handles_missing_or_invalid() -> None:
    assert language_from_attributes(None) is None
    assert language_from_attributes({}) is None
    # Attribute present but empty.
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: ""}) is None
    # Attribute present but a non-string value (e.g. accidentally None).
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: None}) is None  # type: ignore[dict-item]
    # Whitespace-only value normalizes away.
    assert language_from_attributes({LANGUAGE_ATTRIBUTE: "   "}) is None
    # Unrelated attributes don't accidentally trigger a positive return.
    assert language_from_attributes({"event_type": "user.profile.updated.v1"}) is None
