"""Tests for the per-language capability registry.

Mirrors kielo-shared/locale/capability_test.go (Go side). Adding a new
test here should also add the equivalent Go test (and vice versa) to
keep the two halves of the registry consistent.
"""

from kielo_shared.locale.capability import (
    lookup_capability,
    supported_capabilities,
)
from kielo_shared.locale_constants import (
    SUPPORTED_LEARNING_LANGUAGES,
    language_display_name,
)


def test_lookup_capability_happy_path():
    fi = lookup_capability("fi")
    assert fi is not None
    assert fi.code == "fi"
    assert fi.display.display_name_en == "Finnish"
    assert fi.display.country_context == "Finland"
    assert fi.morphology.spacy_pipeline == "fi_core_news_sm"
    assert "partitive" in fi.morphology.exclusive_cases
    assert fi.morphology.has_base_word_lookup is True

    sv = lookup_capability("sv")
    assert sv is not None
    assert sv.code == "sv"
    assert sv.display.display_name_en == "Swedish"
    assert sv.morphology.exclusive_cases == ()
    assert sv.morphology.has_base_word_lookup is False
    assert sv.morphology.post_llm_cleanup_passes == ("rejoin_swedish_definites",)


def test_lookup_capability_normalizes_aliases():
    # "sv-SE" → "sv"
    cap = lookup_capability("sv-SE")
    assert cap is not None
    assert cap.code == "sv"

    # "fi_FI" → "fi"
    cap = lookup_capability("fi_FI")
    assert cap is not None
    assert cap.code == "fi"


def test_lookup_capability_rejects_unsupported():
    # Localization-only locale ("vi") is NOT an authored learning
    # language. Phase 10C no-silent-fallback contract.
    assert lookup_capability("vi") is None
    assert lookup_capability("") is None
    assert lookup_capability("garbage") is None
    assert lookup_capability(None) is None


def test_supported_capabilities_covers_supported_learning_languages():
    # Every code in SUPPORTED_LEARNING_LANGUAGES must have a
    # capability record. The reverse must also hold — adding a row to
    # the _CAPABILITIES dict must also extend the supported-languages
    # set. This test catches drift between the two.
    caps = supported_capabilities()
    assert len(caps) == len(SUPPORTED_LEARNING_LANGUAGES), (
        f"len mismatch: SUPPORTED_LEARNING_LANGUAGES={sorted(SUPPORTED_LEARNING_LANGUAGES)} "
        f"capabilities={[c.code for c in caps]}"
    )

    got = {c.code for c in caps}
    for code in SUPPORTED_LEARNING_LANGUAGES:
        assert code in got, f"supported language {code!r} has no capability record"


def test_supported_capabilities_order_matches_canonical():
    # Order must be deterministic for fan-out scripts (admin tooling,
    # migration runners). Both sides use sorted(SUPPORTED_LEARNING_LANGUAGES).
    caps = supported_capabilities()
    sorted_supported = sorted(SUPPORTED_LEARNING_LANGUAGES)
    for i, cap in enumerate(caps):
        assert cap.code == sorted_supported[i], (
            f"index {i}: cap.code={cap.code!r} sorted_supported={sorted_supported[i]!r}"
        )


def test_capability_display_name_matches_shared_display_name():
    # display.display_name_en MUST match locale_constants.language_display_name(code).
    # Otherwise a registry lookup returns one name and the shared
    # helper returns another — drift hazard for any UI text that
    # mixes both.
    for cap in supported_capabilities():
        shared = language_display_name(cap.code, fallback="")
        assert shared == cap.display.display_name_en, (
            f"capability[{cap.code!r}].display.display_name_en="
            f"{cap.display.display_name_en!r} but "
            f"language_display_name({cap.code!r})={shared!r}"
        )


def test_capability_all_required_slots_present():
    # Required-slot policy (post-2026-05-25 registry coverage audit):
    # only fields with at least one production consumer remain in the
    # required set. Mirrors the Go-side assertion in capability_test.go.
    #
    # Required-slot policy (pruned from scoping §C.3):
    #   - code: required
    #   - display.display_name_en: required (consumed by ktv_locale,
    #     admin_handler, voiceagent, nlp_utils, etc.)
    #   - display.country_context: required for LLM scenario prompts
    #   - morphology.spacy_pipeline: required (kielo-models NLP service)
    #   - caption.scene_greeting / scene_verb / scene_default: required
    #     (kielo-cms ktv_locale.go)
    for cap in supported_capabilities():
        assert cap.code, "code is required"
        assert cap.display.display_name_en, (
            f"display.display_name_en is required for {cap.code!r}"
        )
        assert cap.display.country_context, (
            f"display.country_context is required for {cap.code!r}"
        )
        assert cap.morphology.spacy_pipeline, (
            f"morphology.spacy_pipeline is required for {cap.code!r}"
        )
        assert cap.caption.scene_greeting, (
            f"caption.scene_greeting is required for {cap.code!r}"
        )
        assert cap.caption.scene_verb, (
            f"caption.scene_verb is required for {cap.code!r}"
        )
        assert cap.caption.scene_default, (
            f"caption.scene_default is required for {cap.code!r}"
        )


def test_capability_python_go_parity():
    # Sanity check: the codes registered on the Python side match the
    # codes documented in SUPPORTED_LEARNING_LANGUAGES (which Go
    # mirrors via supportedLearningLanguages). Without this, the Go
    # registry could add a code that the Python side doesn't have —
    # drift hazard.
    py_codes = {c.code for c in supported_capabilities()}
    expected = set(SUPPORTED_LEARNING_LANGUAGES)
    assert py_codes == expected, (
        f"Python registry codes {py_codes} != SUPPORTED_LEARNING_LANGUAGES "
        f"{expected}; ensure both halves of the registry stay in sync."
    )
