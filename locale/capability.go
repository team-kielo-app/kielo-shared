package locale

// Capability is the consolidated per-language metadata record for
// every Kielo service that needs to dispatch on the active learning
// language. The Phase 10B "Capability Registry" backlog item asks for
// a formal single-source-of-truth so adding a new authored learning
// language (today: fi/sv only) doesn't require touching ~90 scattered
// `if language_code == "X"` branches.
//
// This first slice (commit slice 1) introduces the schema + populates
// it with data already present in `kielo-cms`, `kielolearn-engine`,
// `kielo-convo`, and other services. Subsequent slices migrate
// individual call sites to read from `Capability(code)` instead of
// their local hard-coded maps.
//
// Design principles:
//   - DATA ONLY: capability records carry static per-language data
//     (names, hashtags, scene descriptions, prompt fragments, etc.).
//     Behavior dispatch (which morphology backend to invoke, which
//     post-LLM cleanup pass to run) stays in adapter classes that
//     READ from this registry. The split is per the scoping report's
//     §E.5 risk: don't blur capability-as-data with behavior.
//   - REQUIRED CODE LOOKUP: Capability(code) returns (nil, false) for
//     unsupported or empty codes. Callers MUST handle the bool — no
//     silent fi-default (matches Phase 10C contract).
//   - OPTIONAL FIELDS: every sub-record uses zero-value-safe types
//     (empty string, nil slice, empty map) so adding a new language
//     can omit fields that don't apply.
//   - MIRRORED IN PYTHON: kielo-shared/kielo_shared/locale/capability.py
//     carries the equivalent dataclass shape. Adding a new field
//     requires updating BOTH sides + the contract test that compares
//     them.

// MorphologyCapability declares which morphology backend serves the
// language and which optional features it supports. Populated from the
// scoping report §B.1.
type MorphologyCapability struct {
	// PrimaryBackend names the kielo-models morphology backend that
	// serves this language. One of "voikko", "omorfi",
	// "swedish_morphology", or "spacy_only". Required.
	PrimaryBackend string
	// LocalFallbackModule names a Python module the engine can import
	// for offline / models-unreachable fallback. "" if none.
	LocalFallbackModule string
	// HasParadigmGenerator: true if the backend can emit a full
	// declension/conjugation paradigm. Required.
	HasParadigmGenerator bool
	// SpacyPipeline names the spaCy pipeline (e.g. "fi_core_news_sm",
	// "sv_core_news_sm"). "" if no spaCy support.
	SpacyPipeline string
	// ExclusiveCases names morphological cases unique to this language
	// (Finnish: partitive, essive, inessive, etc.; Swedish: none).
	// Used to gate per-language paradigm-form helpers.
	ExclusiveCases []string
	// PostLLMCleanupPasses names post-LLM cleanup passes to apply
	// after simplification / translation steps. Each name resolves to
	// a function in the kielo-ingest-processor at runtime. Empty
	// slice = no language-specific cleanup. Example: Swedish uses
	// {"rejoin_swedish_definites"} to repair LLM-emitted split
	// definite suffixes ("tester na" → "testerna").
	PostLLMCleanupPasses []string
	// HasBaseWordLookup: true if the dictionary feature should
	// consult klearn.base_words via GetBaseWordByTerm before
	// falling through to the generic morphology pipeline. Phase 12
	// slice 7. Currently fi-only — sv's morphology stack handles
	// lemma lookup directly without a klearn round-trip.
	HasBaseWordLookup bool
}

// DisplayCapability covers human-readable labels for prompts, UI, and
// caption decoration. Populated from §B.2, §B.6, §B.7, §B.13.
type DisplayCapability struct {
	// DisplayNameEn is the language's English name (e.g. "Finnish").
	// Required; sourced from languageDisplayNames for consistency.
	DisplayNameEn string
	// CountryContext is the country most associated with this language
	// (e.g. "Finland" / "Sweden") for LLM scenario prompts.
	CountryContext string
	// CapitalScene is a short cultural-backdrop sentence used as the
	// default simplified-prompt scene.
	CapitalScene string
	// NativeScriptHashtags is the curated set of native-script
	// hashtags appended to KTV captions (e.g. ["#suomi","#suomenkieli"]
	// for fi, ["#svenska"] for sv).
	NativeScriptHashtags []string
	// DailyChallengeThemeName is the per-language "Daily Life" /
	// equivalent theme label.
	DailyChallengeThemeName string
	// DefaultKtvVocabularySourceURL is the curated default URL the
	// KTV vocabulary importer uses when no req.SourceURL is supplied
	// AND no manual words list is supplied. Empty string means "no
	// default — caller must provide an explicit source URL." Phase
	// 12 slice 7: previously hard-coded as a Finnish-only constant
	// in kielo-cms/internal/services/ktv_vocabulary_importer.go.
	DefaultKtvVocabularySourceURL string
}

// TTSCapability covers per-language gpt-4o-mini-tts configuration.
// Populated from §B.4.
type TTSCapability struct {
	// PronunciationInstructions is appended to the gpt-4o-mini-tts
	// `instructions` parameter to nudge the model toward correct
	// pronunciation. "" leaves the default English-trained behavior.
	PronunciationInstructions string
	// PreferredVoiceID lets the registry pin a non-default voice when
	// the platform supports it. "" means use the platform default.
	PreferredVoiceID string
}

// STTCapability covers per-language Whisper / Deepgram configuration.
// Populated from §B.5.
type STTCapability struct {
	// WhisperLanguageTag is the language tag passed to Whisper at
	// transcription time. Usually identical to the code, but explicit
	// so we don't assume.
	WhisperLanguageTag string
	// DeepgramSupported: true if the language can be used with the
	// Deepgram voice-agent provider.
	DeepgramSupported bool
}

// CaptionCapability covers per-language KTV / social caption decoration.
// Populated from §B.6 and §B.7.
type CaptionCapability struct {
	// SceneGreeting / SceneVerb / SceneDefault are the per-archetype
	// scene-defaults used by the simplified-prompt fallback (matches
	// the old localeSceneDefaults map in kielo-cms/internal/services/
	// ktv_locale.go). "" means no curated scene (visibly broken
	// output surfaces the misshaped caller per Phase 10C).
	SceneGreeting string
	SceneVerb     string
	SceneDefault  string
}

// SeedVocabularyCapability covers per-language foundational vocabulary
// seeds: starter pronouns, the verb "to be", etc. Used by beginner-
// bootstrap session generation, language detection, STT confidence
// gates. Populated from scoping §B.8.
//
// Slice 5 of the Phase 10B migration: currently carries only the
// starter pronouns + "to be" word for beginner bootstrap. Future
// slices may add common_words, termination_phrases,
// detection_hint_tokens, etc. from the §B.8 inventory.
type SeedVocabularyCapability struct {
	// StarterPronouns maps a semantic slot ("i", "you", "be") to the
	// canonical word for that slot in this language. Used by
	// _build_static_beginner_bootstrap_session in the engine.
	// Required keys today: "i", "you", "be". Adding a new slot
	// requires extending both fi + sv entries in this registry
	// AND every caller that reads from it.
	StarterPronouns map[string]string
}

// GrammarCapability covers per-language LLM-prompt grammar fragments
// + grammar-terminology hints used by the ingest pipeline + engine.
// Populated from scoping §B.9 + §B.11. Read primarily by the ingest
// processor's _llm_handlers.py and kielolearn-engine's dictionary
// enrichment.
type GrammarCapability struct {
	// LanguageFeaturesDescription is the short prose description of
	// the language's distinguishing features (e.g. agglutination,
	// vowel harmony for Finnish; V2 word order, en/ett gender for
	// Swedish), injected into LLM prompts so the model knows what
	// kind of language it's processing.
	LanguageFeaturesDescription string
	// CaseExamples maps a grammar-feature axis ("case", "tense", etc.)
	// to a JSON-array-shaped example string used in batch LLM prompts
	// (e.g. for fi case: `"nominative", "genitive", "partitive"`).
	CaseExamples map[string]string
	// NonNativeTermIssueCode is the audit-issue identifier emitted by
	// the grammar-quality reviewer when a "term" field in a grammar
	// concept doesn't match the expected learning language (e.g. a
	// supposedly-Finnish term that lingua detects as English).
	// Phase 12 slice 6: previously hard-coded as
	// "possible_non_finnish_term" everywhere in
	// kielo-ingest-processor/maintenance/grammar_quality.py — a
	// latent bug that mis-labelled Swedish-language audit findings
	// with the Finnish issue code. Adding a new authored learning
	// language now requires only setting this field.
	NonNativeTermIssueCode string
}

// PromptCapability covers per-language LLM-prompt fragments + scenario
// seed phrases used by kielo-convo and kielo-cms. Populated from §B.11
// and partially §B.10.
type PromptCapability struct {
	// ScenarioGreetMessage / ScenarioGreetTranslation / etc. are the
	// per-language seed phrases used by buildGeneratePrompt in
	// kielo-convo go_orchestrator (scenarioPromptExamples). Translation
	// is the English gloss shown to the LLM for context.
	ScenarioGreetMessage     string
	ScenarioGreetTranslation string
	ScenarioAskMessage       string
	ScenarioAskTranslation   string
	ScenarioHintWouldLike    string
	ScenarioHintHelp         string
	ScenarioHintLookingFor   string
	ScenarioHintNeed         string
	// PoliteExamples is the comma-separated "polite phrase" list for
	// the A1 LLM prompt (G18). e.g. "kiitos, anteeksi, hei".
	PoliteExamples string
	// OfflineTranslationFallbacks is the Finnish-only offline
	// translation dictionary from kielo-cms (G7). Empty for sv.
	OfflineTranslationFallbacks map[string]string
	// Phase 12 slice 9: convo agent prompt-table fields.
	// NeverSayWords is the per-language set of words the LLM must
	// not emit (e.g. "kielimalli", "tekoäly" for Finnish — terms
	// that would break immersion). Read by
	// kielo-convo/python_agent/prompts/compiler.py.
	NeverSayWords []string
	// TerminationPhrase is the per-language goodbye phrase the LLM
	// uses to signal session end. e.g. "Näkemiin" for fi.
	TerminationPhrase string
	// ThankEndPhrase is the per-language session-closure phrase
	// combining a thank-you with the termination. e.g.
	// "Kiitos käynnistä, näkemiin!" for fi.
	ThankEndPhrase string
	// EncourageWords is the per-language list of short encourage
	// interjections the LLM peppers into responses. e.g. ["Hyvä!",
	// "Hienosti!"] for fi.
	EncourageWords []string
	// AckWords is the per-language list of short acknowledgement
	// interjections. e.g. ["Joo!", "Aivan!"] for fi.
	AckWords []string
	// BookingQuestion + BookingAnswer is the per-language scripted
	// "have you got a reservation?" pair used as a few-shot example
	// in scenario prompts. Empty strings = no example available.
	BookingQuestion string
	BookingAnswer   string
}

// Capability is the top-level per-language record.
type Capability struct {
	// Code is the canonical learning-language code ("fi", "sv").
	Code string
	// Display covers labels, country, hashtags, scene defaults.
	Display DisplayCapability
	// Morphology covers backend / paradigm / spaCy pipeline.
	Morphology MorphologyCapability
	// TTS covers gpt-4o-mini-tts pronunciation prose.
	TTS TTSCapability
	// STT covers Whisper / Deepgram support.
	STT STTCapability
	// Caption covers KTV / social caption decoration.
	Caption CaptionCapability
	// Grammar covers per-language LLM-prompt grammar fragments +
	// distinguishing-feature description.
	Grammar GrammarCapability
	// SeedVocab covers per-language foundational vocabulary seeds
	// (starter pronouns, beginner bootstrap words).
	SeedVocab SeedVocabularyCapability
	// Prompts covers per-language LLM prompt fragments.
	Prompts PromptCapability
}

// capabilities is the package-private registry. Keyed by canonical code.
// Adding a new authored learning language requires (1) registering a
// row here, (2) extending SupportedLearningLanguages in locale.go,
// (3) updating the supportedLearningLanguageIdents allowlist in
// kielo-shared/db/searchpath.go, and (4) adding the equivalent record
// to the Python registry. The contract test in capability_test.go
// validates the (1)+(2) consistency.
var capabilities = map[string]*Capability{
	"fi": {
		Code: "fi",
		Display: DisplayCapability{
			DisplayNameEn:           "Finnish",
			CountryContext:          "Finland",
			CapitalScene:            "Helsinki tram stop on a bright weekday morning.",
			NativeScriptHashtags:          []string{"#suomi", "#suomenkieli"},
			DailyChallengeThemeName:       "Arki",
			DefaultKtvVocabularySourceURL: "https://uusikielemme.fi/finnish-vocabulary",
		},
		Morphology: MorphologyCapability{
			HasBaseWordLookup:    true,
			PrimaryBackend:       "voikko",
			LocalFallbackModule:  "", // no offline fallback for fi
			HasParadigmGenerator: true,
			SpacyPipeline:        "fi_core_news_sm",
			ExclusiveCases:       []string{"partitive", "essive", "inessive", "elative", "illative", "adessive", "ablative", "allative"},
			PostLLMCleanupPasses: []string{}, // none currently — pronoun-repair runs inline in exercise_quality_gate, not as a registry-driven post-LLM pass
		},
		TTS: TTSCapability{
			// Phase 10B slice 3: pronunciation prose moved into the
			// registry. The engine's tts_service.py prefers the env
			// override (settings.OPENAI_TTS_FI_INSTRUCTIONS) when
			// set, falling back to this default; python_agent's
			// _build_tts_instructions reads this directly.
			PronunciationInstructions: "Pronounce Finnish naturally with native Finnish phonetics: " +
				"double consonants and long vowels held distinctly, stress on " +
				"the first syllable of each word, clear ä/ö/y vowels (not " +
				"anglicised). Use a warm, friendly, conversational tone.",
			PreferredVoiceID: "",
		},
		STT: STTCapability{
			WhisperLanguageTag: "fi",
			DeepgramSupported:  true,
		},
		Caption: CaptionCapability{
			SceneGreeting: "Helsinki tram stop on a bright weekday morning.",
			SceneVerb:     "Office break room before the first meeting.",
			SceneDefault:  "Kitchen at home before heading out for the day.",
		},
		Grammar: GrammarCapability{
			LanguageFeaturesDescription: "agglutination, vowel harmony, " +
				"15 grammatical cases, no grammatical gender, " +
				"consonant gradation (kpt rules), partitive case, " +
				"essive/translative cases.",
			CaseExamples: map[string]string{
				"case": `"nominative", "genitive", "partitive"`,
			},
			NonNativeTermIssueCode: "possible_non_finnish_term",
		},
		SeedVocab: SeedVocabularyCapability{
			StarterPronouns: map[string]string{
				"i":   "minä",
				"you": "sinä",
				"be":  "olla",
			},
		},
		Prompts: PromptCapability{
			// Phase 10B slice 3: mirrors the source-of-truth strings
			// from kielo-convo go_orchestrator scenarioPromptExamples
			// switch statement that this registry replaces. The
			// hint-* fields are Finnish phrases used as concrete
			// LLM-prompt examples (not the bracketed-English
			// placeholders the legacy fallback branch produced).
			ScenarioGreetMessage:     "Terve! Voinko auttaa?",
			ScenarioGreetTranslation: "Hello! Can I help?",
			ScenarioAskMessage:       "Mitä etsit?",
			ScenarioAskTranslation:   "What are you looking for?",
			ScenarioHintWouldLike:    "Haluaisin...",
			ScenarioHintHelp:         "Voisitko auttaa minua?",
			ScenarioHintLookingFor:   "Etsin...",
			ScenarioHintNeed:         "Tarvitsen...",
			PoliteExamples:           "kiitos, anteeksi, hei",
			OfflineTranslationFallbacks: map[string]string{
				"moi":        "hi (casual greeting)",
				"hei":        "hi / hello",
				"kiitos":     "thank you",
				"puhua":      "to speak",
				"ymmärtää":   "to understand",
				"sanoa":      "to say",
				"kysyä":      "to ask",
				"vastata":    "to answer",
				"tervetuloa": "welcome",
				"anteeksi":   "sorry / excuse me",
			},
			NeverSayWords:     []string{"kielimalli", "tekoäly"},
			TerminationPhrase: "Näkemiin",
			ThankEndPhrase:    "Kiitos käynnistä, näkemiin!",
			EncourageWords:    []string{"Hyvä!", "Hienosti!"},
			AckWords:          []string{"Joo!", "Aivan!", "Hyvä!", "Juuri niin!"},
			BookingQuestion:   "Onko teillä varausta?",
			BookingAnswer:     "Ei hätää, voin tehdä varauksen nyt.",
		},
	},
	"sv": {
		Code: "sv",
		Display: DisplayCapability{
			DisplayNameEn:           "Swedish",
			CountryContext:          "Sweden",
			CapitalScene:            "Stockholm subway platform on a bright weekday morning.",
			NativeScriptHashtags:          []string{"#svenska"},
			DailyChallengeThemeName:       "Vardag",
			DefaultKtvVocabularySourceURL: "",
		},
		Morphology: MorphologyCapability{
			HasBaseWordLookup:    false,
			PrimaryBackend:       "swedish_morphology",
			LocalFallbackModule:  "swedish_morphology",
			HasParadigmGenerator: true,
			SpacyPipeline:        "sv_core_news_sm",
			ExclusiveCases:       []string{}, // none unique to Swedish
			PostLLMCleanupPasses: []string{"rejoin_swedish_definites"},
		},
		TTS: TTSCapability{
			// Phase 10B slice 3: see fi entry.
			PronunciationInstructions: "Pronounce Swedish naturally with native Swedish phonetics: " +
				"the pitch-accent system (acute and grave) honored, å/ä/ö " +
				"as distinct vowels (not anglicised), sj-/tj- sounds soft. " +
				"Use a warm, friendly, conversational tone.",
			PreferredVoiceID: "",
		},
		STT: STTCapability{
			WhisperLanguageTag: "sv",
			DeepgramSupported:  true,
		},
		Caption: CaptionCapability{
			SceneGreeting: "Stockholm subway platform on a bright weekday morning.",
			SceneVerb:     "Office break room before the first meeting.",
			SceneDefault:  "Kitchen at home before heading out for the day.",
		},
		Grammar: GrammarCapability{
			LanguageFeaturesDescription: "V2 word order, two genders " +
				"(en/ett — common vs neuter), definite article via " +
				"suffix (-en/-et/-na), no case marking on nouns, " +
				"verb conjugation primarily for tense (no person/" +
				"number agreement).",
			CaseExamples: map[string]string{
				"case": `"definite", "indefinite", "genitive"`,
			},
			NonNativeTermIssueCode: "possible_non_swedish_term",
		},
		SeedVocab: SeedVocabularyCapability{
			StarterPronouns: map[string]string{
				"i":   "jag",
				"you": "du",
				"be":  "vara",
			},
		},
		Prompts: PromptCapability{
			// Phase 10B slice 3: mirrors source-of-truth strings from
			// kielo-convo go_orchestrator scenarioPromptExamples.
			ScenarioGreetMessage:     "Hej! Vad kan jag hjälpa dig med?",
			ScenarioGreetTranslation: "Hello! What can I help you with?",
			ScenarioAskMessage:       "Vad letar du efter?",
			ScenarioAskTranslation:   "What are you looking for?",
			ScenarioHintWouldLike:    "Jag skulle vilja...",
			ScenarioHintHelp:         "Kan du hjälpa mig?",
			ScenarioHintLookingFor:   "Jag letar efter...",
			ScenarioHintNeed:         "Jag behöver...",
			PoliteExamples:           "tack, ursäkta, hej",
			OfflineTranslationFallbacks: map[string]string{}, // no Swedish offline dictionary yet
			NeverSayWords:               []string{"språkmodell", "ai"},
			TerminationPhrase:           "Hej då",
			ThankEndPhrase:              "Tack för besöket, hej då!",
			EncourageWords:              []string{"Bra!", "Snyggt!"},
			AckWords:                    []string{"Ja!", "Precis!", "Bra!", "Just det!"},
			BookingQuestion:             "Har ni en bokning?",
			BookingAnswer:               "Inga problem, jag kan boka åt er nu.",
		},
	},
}

// LookupCapability returns the capability record for the given
// learning language code. The code is normalized via
// NormalizeSupportedLearningLanguageCode first; codes that don't
// resolve to a supported authored learning language return (nil, false).
//
// Callers MUST handle the (nil, false) case explicitly. The Phase 10C
// "no silent fi-default" contract applies — switch-statements that
// previously fell through to "fi" must now emit an error or empty
// output instead.
func LookupCapability(code string) (*Capability, bool) {
	normalized := NormalizeSupportedLearningLanguageCode(code)
	if normalized == "" {
		return nil, false
	}
	entry, ok := capabilities[normalized]
	return entry, ok
}

// SupportedCapabilities returns all registered capability records in
// the order of SupportedLearningLanguages() (canonical alphabetical).
// Used by contract tests, admin tooling, and migration scripts that
// fan out across every authored language.
func SupportedCapabilities() []*Capability {
	codes := SupportedLearningLanguages()
	out := make([]*Capability, 0, len(codes))
	for _, code := range codes {
		if entry, ok := capabilities[code]; ok {
			out = append(out, entry)
		}
	}
	return out
}
