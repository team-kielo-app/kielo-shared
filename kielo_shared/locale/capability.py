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

    REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
      * primary_backend, local_fallback_module, has_paradigm_generator
        — populated but never read outside kielo-shared. See the
        capability.go REMOVED-* comments for rationale.
    """

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

    has_base_word_lookup: bool = False
    """True if the dictionary feature should consult
    klearn.base_words via GetBaseWordByTerm before falling through
    to the generic morphology pipeline. Phase 12 slice 7."""


@dataclass(frozen=True)
class DisplayCapability:
    """Human-readable labels for prompts, UI, and caption decoration.

    Mirrors kielo-shared/locale/DisplayCapability (Go).

    REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
      * capital_scene — duplicated by Caption.scene_greeting (which
        IS consumed by ktv_locale.go); pure overlap.
      * daily_challenge_theme_name — populated but never read.
    """

    display_name_en: str
    """English name of the language (e.g. "Finnish"). Required; must
    match locale_constants.language_display_name(code)."""

    country_context: str = ""
    """Country most associated with this language (e.g. "Finland")
    for LLM scenario prompts."""

    native_script_hashtags: tuple[str, ...] = ()
    """Curated native-script hashtags appended to KTV captions
    (e.g. ("#suomi", "#suomenkieli") for fi)."""

    default_ktv_vocabulary_source_url: str = ""
    """Curated default URL the KTV vocabulary importer uses when
    no req.SourceURL and no manual words list are supplied. Empty
    string means "no default — caller must provide an explicit
    source URL." Phase 12 slice 7."""


@dataclass(frozen=True)
class TTSCapability:
    """Per-language gpt-4o-mini-tts configuration.

    REMOVED 2026-05-25 (registry coverage audit):
      * preferred_voice_id — populated as None for both fi+sv;
        never read.
    """

    pronunciation_instructions: Optional[str] = None
    """Appended to gpt-4o-mini-tts `instructions` to nudge correct
    pronunciation. None leaves the default English-trained behavior."""


@dataclass(frozen=True)
class STTCapability:
    """Per-language Whisper / Deepgram configuration.

    Currently EMPTY after Phase 12 cleanup. Re-add fields when a
    real consumer materializes.

    REMOVED 2026-05-25 (registry coverage audit):
      * whisper_language_tag — populated as the language code itself
        for both fi+sv; Whisper integration hard-codes elsewhere.
      * deepgram_supported — populated True for both; never queried.
    """
    pass


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

    common_words: tuple[str, ...] = ()
    """Per-language set of common function words used by the voice
    pipeline to disambiguate ambiguous STT outputs. Phase 12 slice 9."""

    termination_phrases: tuple[str, ...] = ()
    """Per-language set of phrases indicating the user wants to end
    the session. The English-language termination set is shared
    globally and added on top by the voice pipeline.
    Phase 12 slice 9."""


@dataclass(frozen=True)
class CaseRuleSpec:
    """Single per-case quality-rule entry. Phase 13 slice 13C.

    Mirrors kielo-shared/locale/CaseRuleSpec (Go). Read by
    kielo-ingest-processor/maintenance/grammar_quality.py's
    _find_case_rule to detect suffix-mismatch and category-mismatch
    issues in grammar concept explanations.
    """

    canonical_suffixes: tuple[str, ...] = ()
    """Suffixes that SHOULD appear in a correct explanation for this case."""

    wrong_suffixes: tuple[str, ...] = ()
    """Suffixes that, if present, indicate the concept is mixing
    this case with another."""

    category_keywords: tuple[str, ...] = ()
    """Keywords that must appear in the concept's category field for
    this rule to NOT flag a category-mismatch issue."""

    safe_time_explanation: str = ""
    """Prose used by the deterministic patch path when fixing a
    misexplained case."""


@dataclass(frozen=True)
class GrammarCapability:
    """Per-language LLM-prompt grammar fragments + grammar-terminology hints.

    Populated from scoping §B.9 + §B.11. Read primarily by the ingest
    processor's _llm_handlers.py and kielolearn-engine's dictionary
    enrichment.

    Mirrors kielo-shared/locale/GrammarCapability (Go).

    REMOVED 2026-05-25 (registry coverage audit):
      * language_features_description — never read in production
        code. nlp_utils.py:1043 had a comment saying the local
        _LANGUAGE_FEATURES dict was *deliberately* kept divergent
        from this field. The two strings drifted; this field was
        actively misleading.
    """

    case_examples: Mapping[str, str] = field(default_factory=dict)
    """Maps a grammar-feature axis ("case", "tense", etc.) to a
    JSON-array-shaped example string for batch LLM prompts (e.g. for
    fi case: '"nominative", "genitive", "partitive"')."""

    case_rules: Mapping[str, CaseRuleSpec] = field(default_factory=dict)
    """Per-language map keyed by case-name term (case-folded) to that
    case's suffix-rule + category metadata. Phase 13 slice 13C."""

    non_native_term_issue_code: str = ""
    """Audit-issue identifier emitted by the grammar-quality reviewer
    when a "term" field in a grammar concept doesn't match the
    expected learning language. Phase 12 slice 6: drains a latent
    bug in kielo-ingest-processor/maintenance/grammar_quality.py
    where every audit row was labelled "possible_non_finnish_term"
    regardless of the actual learning language."""


@dataclass(frozen=True)
class PhraseFrameSpec:
    """Single phrase-frame template tuple. Phase 12 slice 12.

    Mirrors kielo-shared/locale/PhraseFrameSpec (Go). Read by
    kielolearn-engine's dictionary_enrichment to build rule-based
    fill-in-the-blank phrase frames when no LLM result is available.

    frame_text contains "___" (literal frame).
    example_text contains "{term}" — interpolated with the actual term.
    example_translation contains "{gloss}" — interpolated with the
    English gloss.
    """

    frame_text: str = ""
    example_text: str = ""
    example_translation: str = ""


@dataclass(frozen=True)
class PhraseFrameTemplates:
    """Per-language POS-bucketed phrase-frame templates.
    Phase 12 slice 12."""

    verb: PhraseFrameSpec = field(default_factory=PhraseFrameSpec)
    adj: PhraseFrameSpec = field(default_factory=PhraseFrameSpec)
    adv: PhraseFrameSpec = field(default_factory=PhraseFrameSpec)
    default: PhraseFrameSpec = field(default_factory=PhraseFrameSpec)


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

    # REMOVED 2026-05-25 (registry coverage audit):
    #   * offline_translation_fallbacks — fi-only (10 entries) AND
    #     completely unconsumed. See capability.go for rationale.

    # Phase 12 slice 9: convo agent prompt-table fields.
    never_say_words: tuple[str, ...] = ()
    """Per-language set of words the LLM must not emit (e.g.
    "kielimalli", "tekoäly" for Finnish). Read by
    kielo-convo/python_agent/prompts/compiler.py."""

    termination_phrase: str = ""
    """Per-language goodbye phrase the LLM uses to signal session
    end (e.g. "Näkemiin" for fi)."""

    thank_end_phrase: str = ""
    """Per-language session-closure phrase combining a thank-you
    with the termination (e.g. "Kiitos käynnistä, näkemiin!" for fi)."""

    encourage_words: tuple[str, ...] = ()
    """Per-language list of short encourage interjections the LLM
    peppers into responses (e.g. ("Hyvä!", "Hienosti!") for fi)."""

    ack_words: tuple[str, ...] = ()
    """Per-language list of short acknowledgement interjections
    (e.g. ("Joo!", "Aivan!") for fi)."""

    booking_question: str = ""
    """Per-language scripted "have you got a reservation?" question
    used as a few-shot example in scenario prompts. Empty = no
    example available for this language."""

    booking_answer: str = ""
    """Per-language scripted answer paired with booking_question."""

    hint_complexity_simple: str = ""
    """Per-language slash-separated example for simple (A1) hint
    complexity. e.g. '"Kiitos!" / "Haluan kahvin." / "Kyllä."' for fi.
    Phase 12 slice 10."""

    hint_complexity_challenge: str = ""
    """Per-language slash-separated example for challenge (B1+) hint
    complexity. Phase 12 slice 10."""

    nudge_openers: Mapping[str, Sequence[str]] = field(default_factory=dict)
    """Per-language map keyed by session phase ("early", "mid",
    "late") returning a list of opening phrases the agent uses to
    nudge the user mid-session. Phase 12 slice 9."""

    try_saying_template: str = ""
    """Per-language template the agent uses to suggest a phrase.
    Must contain "{hint}". e.g. for fi:
    "Kokeile vaikka: '{hint}' (Try saying: '{hint}')". Phase 12 slice 9."""

    no_hint_fallback: str = ""
    """Per-language fallback the agent emits when it has no concrete
    hint to offer. Phase 12 slice 9."""

    wrapping_up: str = ""
    """Per-language phrase the agent emits when approaching the
    session time limit. Phase 12 slice 9."""

    phrase_frame_templates: PhraseFrameTemplates = field(default_factory=PhraseFrameTemplates)
    """Per-language POS-bucketed phrase-frame templates used by
    kielolearn-engine's dictionary enrichment to build rule-based
    fill-in-the-blank phrase frames. Phase 12 slice 12."""


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
            native_script_hashtags=("#suomi", "#suomenkieli"),
            default_ktv_vocabulary_source_url="https://uusikielemme.fi/finnish-vocabulary",
        ),
        morphology=MorphologyCapability(
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
            has_base_word_lookup=True,
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
        ),
        stt=STTCapability(),
        caption=CaptionCapability(
            scene_greeting="Helsinki tram stop on a bright weekday morning.",
            scene_verb="Office break room before the first meeting.",
            scene_default="Kitchen at home before heading out for the day.",
        ),
        grammar=GrammarCapability(
            case_examples={
                "case": '"nominative", "genitive", "partitive"',
            },
            case_rules={
                "adessiivi": CaseRuleSpec(
                    canonical_suffixes=("-lla/-llä",),
                    wrong_suffixes=("-na/-nä",),
                    category_keywords=("case", "locative", "local"),
                    safe_time_explanation=(
                        "The Adessive case (-lla/-llä) is used for broader time periods and settings, "
                        "such as seasons, weeks, months, or general 'during/in' time frames. "
                        "Specific weekdays, dates, and holidays usually use the Essive case (-na/-nä) instead."
                    ),
                ),
                "essiivi": CaseRuleSpec(
                    canonical_suffixes=("-na/-nä",),
                    wrong_suffixes=("-lla/-llä",),
                    category_keywords=("case", "role", "state"),
                    safe_time_explanation=(
                        "The Essive case (-na/-nä) marks a temporary role or state and is also used "
                        "for specific weekdays, dates, and holidays. Broader time periods such as "
                        "seasons or months typically use other cases like the Adessive (-lla/-llä) "
                        "or Inessive (-ssa/-ssä), depending on the expression."
                    ),
                ),
            },
            non_native_term_issue_code="possible_non_finnish_term",
        ),
        seed_vocab=SeedVocabularyCapability(
            starter_pronouns={
                "i": "minä",
                "you": "sinä",
                "be": "olla",
            },
            common_words=(
                "ja", "on", "se", "ei", "en", "niin", "tai", "ole", "olen", "minä", "sinä",
            ),
            termination_phrases=(
                "hyvästi", "näkemiin", "kiitos ja hei", "kiitos, hei", "lopetetaan",
            ),
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
            never_say_words=("kielimalli", "tekoäly"),
            termination_phrase="Näkemiin",
            thank_end_phrase="Kiitos käynnistä, näkemiin!",
            encourage_words=("Hyvä!", "Hienosti!"),
            ack_words=("Joo!", "Aivan!", "Hyvä!", "Juuri niin!"),
            booking_question="Onko teillä varausta?",
            booking_answer="Ei hätää, voin tehdä varauksen nyt.",
            hint_complexity_simple='"Kiitos!" / "Haluan kahvin." / "Kyllä."',
            hint_complexity_challenge=(
                '"Voisinko saada yhden cappuccinon ja pienen pullan, kiitos?" / '
                '"Haluaisin varata ajan huomiselle, jos mahdollista."'
            ),
            nudge_openers={
                "early": (
                    "Hyvä alku! Haluatko jatkaa suomeksi?",
                    "Jatketaan rauhassa. Voit vastata lyhyesti.",
                ),
                "mid": (
                    "Hyvin menee! Kerro vielä yhdellä lauseella.",
                    "Hienosti! Mitä haluaisit sanoa seuraavaksi?",
                ),
                "late": (
                    "Juuri näin, jatketaan vielä hetki.",
                    "Olet hyvässä vauhdissa. Kokeile vielä yksi vastaus.",
                ),
            },
            try_saying_template="Kokeile vaikka: '{hint}' (Try saying: '{hint}')",
            no_hint_fallback="Ei hätää! Voit sanoa ihan mitä vain. (No worries, say anything!)",
            wrapping_up="Meillä on vielä hetki aikaa. Jatketaan rauhassa!",
            phrase_frame_templates=PhraseFrameTemplates(
                verb=PhraseFrameSpec(
                    frame_text="Haluan ___.",
                    example_text="Haluan {term}.",
                    example_translation="I want to {gloss}.",
                ),
                adj=PhraseFrameSpec(
                    frame_text="Se on ___.",
                    example_text="Se on {term}.",
                    example_translation="It is {gloss}.",
                ),
                adv=PhraseFrameSpec(
                    frame_text="Tein sen ___.",
                    example_text="Tein sen {term}.",
                    example_translation="I did it {gloss}.",
                ),
                default=PhraseFrameSpec(
                    frame_text="Tämä on ___.",
                    example_text="Tämä on {term}.",
                    example_translation="This is {gloss}.",
                ),
            ),
        ),
    ),
    "sv": Capability(
        code="sv",
        display=DisplayCapability(
            display_name_en="Swedish",
            country_context="Sweden",
            native_script_hashtags=("#svenska",),
            default_ktv_vocabulary_source_url="",
        ),
        morphology=MorphologyCapability(
            spacy_pipeline="sv_core_news_sm",
            exclusive_cases=(),  # none unique to Swedish
            post_llm_cleanup_passes=("rejoin_swedish_definites",),
            has_base_word_lookup=False,
        ),
        tts=TTSCapability(
            # Phase 10B slice 3: see fi entry.
            pronunciation_instructions=(
                "Pronounce Swedish naturally with native Swedish phonetics: "
                "the pitch-accent system (acute and grave) honored, å/ä/ö "
                "as distinct vowels (not anglicised), sj-/tj- sounds soft. "
                "Use a warm, friendly, conversational tone."
            ),
        ),
        stt=STTCapability(),
        caption=CaptionCapability(
            scene_greeting="Stockholm subway platform on a bright weekday morning.",
            scene_verb="Office break room before the first meeting.",
            scene_default="Kitchen at home before heading out for the day.",
        ),
        grammar=GrammarCapability(
            case_examples={
                "case": '"definite", "indefinite", "genitive"',
            },
            # Phase 13 slice 13C+13F: Swedish quality-gate. See
            # capability.go for the SAG (Svenska Akademiens grammatik)
            # cross-reference notes. Rules are conservative —
            # wrong_suffixes lists ONLY items unambiguously wrong;
            # ambiguous suffixes (e.g. -er which is both indef.pl.3rd
            # and def.sg.5th-decl-neuter) are omitted to avoid false
            # positives. Native-speaker review still recommended
            # before tightening to hard-fail on Swedish content.
            case_rules={
                "bestämd form": CaseRuleSpec(
                    canonical_suffixes=("-en", "-et", "-na"),
                    wrong_suffixes=("-s",),  # -s is unambiguously genitive
                    category_keywords=("noun", "definiteness"),
                    safe_time_explanation=(
                        "Swedish definite form is marked by suffixed articles "
                        "(-en/-et for singular, -na for plural). The -s suffix marks the "
                        "genitive case, NOT definite form."
                    ),
                ),
                "obestämd form": CaseRuleSpec(
                    canonical_suffixes=(),  # indefinite SINGULAR uses ARTICLE, no suffix
                    # Only definite-singular-neuter -et is unambiguously
                    # wrong. Plural -er is ambiguous (also indef.pl.3rd-decl).
                    wrong_suffixes=("-et",),
                    category_keywords=("noun", "definiteness"),
                    safe_time_explanation=(
                        "Swedish indefinite form (singular) takes the article 'en' "
                        "(common gender) or 'ett' (neuter) BEFORE the noun, with no suffix. "
                        "The -et suffix on the noun marks the DEFINITE singular form of a "
                        "neuter noun, not the indefinite."
                    ),
                ),
                "genitiv": CaseRuleSpec(
                    canonical_suffixes=("-s",),
                    wrong_suffixes=("-en", "-et", "-na"),  # def-form suffixes ≠ genitive
                    category_keywords=("noun", "case"),
                    safe_time_explanation=(
                        "Swedish genitive case is formed by adding -s to the noun "
                        "(e.g. 'flickans bok' = 'the girl's book', 'barns leksak' = 'a child's toy'). "
                        "It is NOT marked by the definite-form suffixes -en/-et/-na."
                    ),
                ),
            },
            non_native_term_issue_code="possible_non_swedish_term",
        ),
        seed_vocab=SeedVocabularyCapability(
            starter_pronouns={
                "i": "jag",
                "you": "du",
                "be": "vara",
            },
            common_words=(
                "och", "är", "jag", "du", "vi", "det", "en", "ett", "har", "inte",
                "som", "på", "av", "för", "med", "men", "eller", "om", "när", "var",
            ),
            termination_phrases=(
                "hej då", "adjö", "tack och hej", "vi ses", "hejdå",
            ),
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
            never_say_words=("språkmodell", "ai"),
            termination_phrase="Hej då",
            thank_end_phrase="Tack för besöket, hej då!",
            encourage_words=("Bra!", "Snyggt!"),
            ack_words=("Ja!", "Precis!", "Bra!", "Just det!"),
            booking_question="Har ni en bokning?",
            booking_answer="Inga problem, jag kan boka åt er nu.",
            hint_complexity_simple='"Tack!" / "Jag vill ha kaffe." / "Ja."',
            hint_complexity_challenge=(
                '"Skulle jag kunna få en cappuccino och en liten bulle, tack?" / '
                '"Jag skulle vilja boka en tid till imorgon, om möjligt."'
            ),
            nudge_openers={
                "early": (
                    "Bra start! Vill du fortsätta på svenska?",
                    "Vi tar det lugnt. Du kan svara kort.",
                ),
                "mid": (
                    "Det går bra! Säg en mening till.",
                    "Snyggt! Vad vill du säga härnäst?",
                ),
                "late": (
                    "Precis så, vi fortsätter en stund till.",
                    "Du är på rätt väg. Försök med ett svar till.",
                ),
            },
            try_saying_template="Försök säga: '{hint}' (Try saying: '{hint}')",
            no_hint_fallback="Ingen fara! Du kan säga vad som helst. (No worries, say anything!)",
            wrapping_up="Vi har en stund kvar. Vi fortsätter i lugn takt!",
            phrase_frame_templates=PhraseFrameTemplates(
                verb=PhraseFrameSpec(
                    frame_text="Jag vill ___.",
                    example_text="Jag vill {term}.",
                    example_translation="I want to {gloss}.",
                ),
                adj=PhraseFrameSpec(
                    frame_text="Det är ___.",
                    example_text="Det är {term}.",
                    example_translation="It is {gloss}.",
                ),
                adv=PhraseFrameSpec(
                    frame_text="Jag gjorde det ___.",
                    example_text="Jag gjorde det {term}.",
                    example_translation="I did it {gloss}.",
                ),
                default=PhraseFrameSpec(
                    frame_text="Det här är ___.",
                    example_text="Det här är {term}.",
                    example_translation="This is {gloss}.",
                ),
            ),
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
    "CaseRuleSpec",
    "SeedVocabularyCapability",
    "PromptCapability",
    "PhraseFrameSpec",
    "PhraseFrameTemplates",
    "lookup_capability",
    "supported_capabilities",
]


# Re-export the underscore helper for the contract test that mirrors
# the Go capability test. Internal use only — do not import directly.
_ = language_display_name  # silence unused-import linters
