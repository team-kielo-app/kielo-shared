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

    post_llm_cleanup_passes: tuple[str, ...] = ()
    """Names of post-LLM cleanup passes to apply after simplification
    / translation steps. Each name resolves to a function in the
    kielo-ingest-processor at runtime. Empty tuple = no language-
    specific cleanup. Example: Swedish uses
    ("rejoin_swedish_definites",) to repair LLM-emitted split
    definite suffixes ("tester na" → "testerna")."""


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
class SeedVocabularyCapability:
    """Per-language foundational vocabulary seeds.

    Populated from scoping §B.8. Currently carries only the starter
    pronouns + "be" word for beginner-bootstrap session generation;
    future slices may add common_words, termination_phrases,
    detection_hint_tokens, etc.

    Mirrors kielo-shared/locale/SeedVocabularyCapability (Go).
    """

    starter_pronouns: Mapping[str, str] = field(default_factory=dict)
    """Maps a semantic slot ("i", "you", "be") to the canonical word
    for that slot in this language. Read by the engine's
    _build_static_beginner_bootstrap_session. Required keys today:
    "i", "you", "be"."""


@dataclass(frozen=True)
class GrammarCapability:
    """Per-language LLM-prompt grammar fragments + grammar-terminology hints.

    Populated from scoping §B.9 + §B.11. Read primarily by the ingest
    processor's _llm_handlers.py and kielolearn-engine's dictionary
    enrichment.

    Mirrors kielo-shared/locale/GrammarCapability (Go).
    """

    language_features_description: str = ""
    """Short prose description of the language's distinguishing features
    (e.g. agglutination, vowel harmony for Finnish). Injected into LLM
    prompts so the model knows what kind of language it's processing."""

    case_examples: Mapping[str, str] = field(default_factory=dict)
    """Maps a grammar-feature axis ("case", "tense", etc.) to a
    JSON-array-shaped example string for batch LLM prompts (e.g. for
    fi case: '"nominative", "genitive", "partitive"')."""


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
    grammar: GrammarCapability
    seed_vocab: SeedVocabularyCapability
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
            post_llm_cleanup_passes=(),  # see Go counterpart for rationale
        ),
        tts=TTSCapability(
            # Phase 10B slice 3: pronunciation prose moved into the
            # registry. Engine's tts_service.py prefers the env override
            # (settings.OPENAI_TTS_FI_INSTRUCTIONS) when set, falling
            # back to this default; python_agent's _build_tts_instructions
            # reads this directly.
            pronunciation_instructions=(
                "Pronounce Finnish naturally with native Finnish phonetics: "
                "double consonants and long vowels held distinctly, stress on "
                "the first syllable of each word, clear ä/ö/y vowels (not "
                "anglicised). Use a warm, friendly, conversational tone."
            ),
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
        grammar=GrammarCapability(
            language_features_description=(
                "agglutination, vowel harmony, "
                "15 grammatical cases, no grammatical gender, "
                "consonant gradation (kpt rules), partitive case, "
                "essive/translative cases."
            ),
            case_examples={
                "case": '"nominative", "genitive", "partitive"',
            },
        ),
        seed_vocab=SeedVocabularyCapability(
            starter_pronouns={
                "i": "minä",
                "you": "sinä",
                "be": "olla",
            },
        ),
        prompts=PromptCapability(
            # Phase 10B slice 3: mirrors source-of-truth strings from
            # kielo-convo go_orchestrator scenarioPromptExamples that
            # the registry replaces.
            scenario_greet_message="Terve! Voinko auttaa?",
            scenario_greet_translation="Hello! Can I help?",
            scenario_ask_message="Mitä etsit?",
            scenario_ask_translation="What are you looking for?",
            scenario_hint_would_like="Haluaisin...",
            scenario_hint_help="Voisitko auttaa minua?",
            scenario_hint_looking_for="Etsin...",
            scenario_hint_need="Tarvitsen...",
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
            post_llm_cleanup_passes=("rejoin_swedish_definites",),
        ),
        tts=TTSCapability(
            # Phase 10B slice 3: see fi entry.
            pronunciation_instructions=(
                "Pronounce Swedish naturally with native Swedish phonetics: "
                "the pitch-accent system (acute and grave) honored, å/ä/ö "
                "as distinct vowels (not anglicised), sj-/tj- sounds soft. "
                "Use a warm, friendly, conversational tone."
            ),
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
        grammar=GrammarCapability(
            language_features_description=(
                "V2 word order, two genders "
                "(en/ett — common vs neuter), definite article via "
                "suffix (-en/-et/-na), no case marking on nouns, "
                "verb conjugation primarily for tense (no person/"
                "number agreement)."
            ),
            case_examples={
                "case": '"definite", "indefinite", "genitive"',
            },
        ),
        seed_vocab=SeedVocabularyCapability(
            starter_pronouns={
                "i": "jag",
                "you": "du",
                "be": "vara",
            },
        ),
        prompts=PromptCapability(
            # Phase 10B slice 3: mirrors source-of-truth strings from
            # kielo-convo go_orchestrator scenarioPromptExamples.
            scenario_greet_message="Hej! Vad kan jag hjälpa dig med?",
            scenario_greet_translation="Hello! What can I help you with?",
            scenario_ask_message="Vad letar du efter?",
            scenario_ask_translation="What are you looking for?",
            scenario_hint_would_like="Jag skulle vilja...",
            scenario_hint_help="Kan du hjälpa mig?",
            scenario_hint_looking_for="Jag letar efter...",
            scenario_hint_need="Jag behöver...",
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
    "GrammarCapability",
    "SeedVocabularyCapability",
    "PromptCapability",
    "lookup_capability",
    "supported_capabilities",
]


# Re-export the underscore helper for the contract test that mirrors
# the Go capability test. Internal use only — do not import directly.
_ = language_display_name  # silence unused-import linters
