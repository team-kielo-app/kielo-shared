"""Per-language capability registry — Python mirror of locale.Capability.

The Phase 10B "Capability Registry" backlog item asks for a formal
single-source-of-truth so adding a new authored learning language
(today: fi/sv only) doesn't require touching ~90 scattered
`if language_code == "X"` branches across Python and Go services.

This module is the Python half of the registry. The Go half lives at
`kielo-shared/locale/capability.go`. The two MUST stay in sync —
adding a new field requires updating both sides plus the contract
test that compares them.

Design principles:
  - DATA ONLY: capability records carry static per-language data
    (names, hashtags, scene descriptions, prompt fragments, etc.).
    Behavior dispatch (which morphology backend to invoke, which
    post-LLM cleanup pass to run) stays in adapter classes that
    READ from this registry. Don't blur capability-as-data with
    behavior.
  - REQUIRED CODE LOOKUP: `lookup_capability(code)` returns None for
    unsupported or empty codes. Callers MUST handle None — no silent
    fi-default (matches Phase 10C contract).
  - OPTIONAL FIELDS: every dataclass field has a zero-value-safe
    default (empty string, empty tuple, empty dict) so adding a new
    language can omit fields that don't apply.
  - MIRRORED IN GO: `kielo-shared/locale/capability.go` carries the
    equivalent struct shape. Contract test must keep them in sync.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from kielo_shared.locale_constants import (
    SUPPORTED_LEARNING_LANGUAGES,
    language_display_name,
    normalize_supported_learning_language_code,
)


@dataclass(frozen=True)
class MorphologyCapability:
    """Which morphology backend serves the language and what it supports.

    Mirrors kielo-shared/locale/MorphologyCapability (Go).
    """

    primary_backend: str
    """Names the kielo-models morphology backend that serves this language.
    One of "voikko", "omorfi", "swedish_morphology", or "spacy_only".
    Required."""

    local_fallback_module: Optional[str] = None
    """Python module name the engine can import for offline / models-
    unreachable fallback. None if no local fallback exists."""

    has_paradigm_generator: bool = False
    """True if the backend can emit a full declension/conjugation
    paradigm. Required."""

    spacy_pipeline: Optional[str] = None
    """spaCy pipeline name (e.g. "fi_core_news_sm"). None if no spaCy
    support."""

    exclusive_cases: tuple[str, ...] = ()
    """Morphological cases unique to this language. Used to gate per-
    language paradigm-form helpers (e.g. Finnish partitive/essive
    extractors)."""


@dataclass(frozen=True)
class DisplayCapability:
    """Human-readable labels for prompts, UI, and caption decoration.

    Mirrors kielo-shared/locale/DisplayCapability (Go).
    """

    display_name_en: str
    """English name of the language (e.g. "Finnish"). Required; must
    match locale_constants.language_display_name(code)."""

    country_context: str = ""
    """Country most associated with this language (e.g. "Finland")
    for LLM scenario prompts."""

    capital_scene: str = ""
    """Short cultural-backdrop sentence used as the default simplified-
    prompt scene."""

    native_script_hashtags: tuple[str, ...] = ()
    """Curated native-script hashtags appended to KTV captions
    (e.g. ("#suomi", "#suomenkieli") for fi)."""

    daily_challenge_theme_name: str = ""
    """Per-language "Daily Life" / equivalent theme label."""


@dataclass(frozen=True)
class TTSCapability:
    """Per-language gpt-4o-mini-tts configuration."""

    pronunciation_instructions: Optional[str] = None
    """Appended to gpt-4o-mini-tts `instructions` to nudge correct
    pronunciation. None leaves the default English-trained behavior."""

    preferred_voice_id: Optional[str] = None
    """Pin a non-default voice when supported. None means platform
    default."""


@dataclass(frozen=True)
class STTCapability:
    """Per-language Whisper / Deepgram configuration."""

    whisper_language_tag: str
    """Language tag passed to Whisper. Usually identical to the code
    but explicit so we don't assume."""

    deepgram_supported: bool = False
    """True if the language can be used with the Deepgram voice-agent
    provider."""


@dataclass(frozen=True)
class CaptionCapability:
    """Per-language KTV / social caption decoration."""

    scene_greeting: str = ""
    """Cultural-backdrop scene for "greeting" archetype."""

    scene_verb: str = ""
    """Scene for "verb" archetype."""

    scene_default: str = ""
    """Default scene archetype."""


@dataclass(frozen=True)
class PromptCapability:
    """Per-language LLM-prompt fragments + scenario seed phrases."""

    scenario_greet_message: str = ""
    scenario_greet_translation: str = ""
    scenario_ask_message: str = ""
    scenario_ask_translation: str = ""
    scenario_hint_would_like: str = ""
    scenario_hint_help: str = ""
    scenario_hint_looking_for: str = ""
    scenario_hint_need: str = ""
    polite_examples: str = ""
    """Comma-separated polite-phrase list for the A1 LLM prompt
    (e.g. "kiitos, anteeksi, hei")."""

    offline_translation_fallbacks: Mapping[str, str] = field(default_factory=dict)
    """Finnish-only offline translation dictionary from kielo-cms (G7).
    Empty for sv."""


@dataclass(frozen=True)
class Capability:
    """Top-level per-language capability record."""

    code: str
    display: DisplayCapability
    morphology: MorphologyCapability
    tts: TTSCapability
    stt: STTCapability
    caption: CaptionCapability
    prompts: PromptCapability


# Package-private registry. Keyed by canonical code.
# Adding a new authored learning language requires:
#   1. Registering a row here.
#   2. Extending SUPPORTED_LEARNING_LANGUAGES in locale_constants.py.
#   3. Updating the supportedLearningLanguageIdents allowlist in
#      kielo-shared/db/searchpath.go (Go side).
#   4. Adding the equivalent record to the Go registry
#      (kielo-shared/locale/capability.go).
# The contract test in test_capability.py validates the (1)+(2) and
# Python↔Go consistency.
_CAPABILITIES: dict[str, Capability] = {
    "fi": Capability(
        code="fi",
        display=DisplayCapability(
            display_name_en="Finnish",
            country_context="Finland",
            capital_scene="Helsinki tram stop on a bright weekday morning.",
            native_script_hashtags=("#suomi", "#suomenkieli"),
            daily_challenge_theme_name="Arki",
        ),
        morphology=MorphologyCapability(
            primary_backend="voikko",
            local_fallback_module=None,  # no offline fallback for fi
            has_paradigm_generator=True,
            spacy_pipeline="fi_core_news_sm",
            exclusive_cases=(
                "partitive",
                "essive",
                "inessive",
                "elative",
                "illative",
                "adessive",
                "ablative",
                "allative",
            ),
        ),
        tts=TTSCapability(
            # Pronunciation prose currently sourced from
            # settings.OPENAI_TTS_FI_INSTRUCTIONS at runtime;
            # registry slot holds the empty default. Slice 3 of the
            # migration plan will move env-loading into here.
            pronunciation_instructions=None,
            preferred_voice_id=None,
        ),
        stt=STTCapability(
            whisper_language_tag="fi",
            deepgram_supported=True,
        ),
        caption=CaptionCapability(
            scene_greeting="Helsinki tram stop on a bright weekday morning.",
            scene_verb="Office break room before the first meeting.",
            scene_default="Kitchen at home before heading out for the day.",
        ),
        prompts=PromptCapability(
            scenario_greet_message="Moi! Mitä kuuluu?",
            scenario_greet_translation="Hi! How are you?",
            scenario_ask_message="Voitko auttaa minua?",
            scenario_ask_translation="Can you help me?",
            scenario_hint_would_like="[I would like... in Finnish]",
            scenario_hint_help="[Can you help me... in Finnish]",
            scenario_hint_looking_for="[I'm looking for... in Finnish]",
            scenario_hint_need="[I need... in Finnish]",
            polite_examples="kiitos, anteeksi, hei",
            offline_translation_fallbacks={
                "moi": "hi (casual greeting)",
                "hei": "hi / hello",
                "kiitos": "thank you",
                "puhua": "to speak",
                "ymmärtää": "to understand",
                "sanoa": "to say",
                "kysyä": "to ask",
                "vastata": "to answer",
                "tervetuloa": "welcome",
                "anteeksi": "sorry / excuse me",
            },
        ),
    ),
    "sv": Capability(
        code="sv",
        display=DisplayCapability(
            display_name_en="Swedish",
            country_context="Sweden",
            capital_scene="Stockholm subway platform on a bright weekday morning.",
            native_script_hashtags=("#svenska",),
            daily_challenge_theme_name="Vardag",
        ),
        morphology=MorphologyCapability(
            primary_backend="swedish_morphology",
            local_fallback_module="swedish_morphology",
            has_paradigm_generator=True,
            spacy_pipeline="sv_core_news_sm",
            exclusive_cases=(),  # none unique to Swedish
        ),
        tts=TTSCapability(
            pronunciation_instructions=None,
            preferred_voice_id=None,
        ),
        stt=STTCapability(
            whisper_language_tag="sv",
            deepgram_supported=True,
        ),
        caption=CaptionCapability(
            scene_greeting="Stockholm subway platform on a bright weekday morning.",
            scene_verb="Office break room before the first meeting.",
            scene_default="Kitchen at home before heading out for the day.",
        ),
        prompts=PromptCapability(
            scenario_greet_message="Hej! Hur mår du?",
            scenario_greet_translation="Hi! How are you?",
            scenario_ask_message="Kan du hjälpa mig?",
            scenario_ask_translation="Can you help me?",
            scenario_hint_would_like="[I would like... in Swedish]",
            scenario_hint_help="[Can you help me... in Swedish]",
            scenario_hint_looking_for="[I'm looking for... in Swedish]",
            scenario_hint_need="[I need... in Swedish]",
            polite_examples="tack, ursäkta, hej",
            offline_translation_fallbacks={},  # no Swedish offline dictionary yet
        ),
    ),
}


def lookup_capability(code: Optional[str]) -> Optional[Capability]:
    """Return the capability record for the given learning language code.

    The code is normalized via ``normalize_supported_learning_language_code``
    first; codes that don't resolve to a supported authored learning
    language return None.

    Callers MUST handle the None case explicitly. The Phase 10C
    "no silent fi-default" contract applies — `if-language == fi`
    branches that previously fell through to fi must now emit an
    error or empty output instead.
    """
    if code is None:
        return None
    normalized = normalize_supported_learning_language_code(code)
    if not normalized:
        return None
    return _CAPABILITIES.get(normalized)


def supported_capabilities() -> Sequence[Capability]:
    """Return all registered capability records in canonical order.

    Order matches ``sorted(SUPPORTED_LEARNING_LANGUAGES)`` (alphabetical
    by code). Used by contract tests, admin tooling, and migration
    scripts that fan out across every authored language.
    """
    return tuple(
        _CAPABILITIES[code]
        for code in sorted(SUPPORTED_LEARNING_LANGUAGES)
        if code in _CAPABILITIES
    )


__all__ = [
    "Capability",
    "MorphologyCapability",
    "DisplayCapability",
    "TTSCapability",
    "STTCapability",
    "CaptionCapability",
    "PromptCapability",
    "lookup_capability",
    "supported_capabilities",
]


# Re-export the underscore helper for the contract test that mirrors
# the Go capability test. Internal use only — do not import directly.
_ = language_display_name  # silence unused-import linters
