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
			NativeScriptHashtags:    []string{"#suomi", "#suomenkieli"},
			DailyChallengeThemeName: "Arki",
		},
		Morphology: MorphologyCapability{
			PrimaryBackend:       "voikko",
			LocalFallbackModule:  "", // no offline fallback for fi
			HasParadigmGenerator: true,
			SpacyPipeline:        "fi_core_news_sm",
			ExclusiveCases:       []string{"partitive", "essive", "inessive", "elative", "illative", "adessive", "ablative", "allative"},
		},
		TTS: TTSCapability{
			// Pronunciation prose is sourced from env at runtime
			// (settings.OPENAI_TTS_FI_INSTRUCTIONS); registry holds
			// the empty default. Slice 3 of the migration plan will
			// move env-loading into here.
			PronunciationInstructions: "",
			PreferredVoiceID:          "",
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
		},
		Prompts: PromptCapability{
			ScenarioGreetMessage:     "Moi! Mitä kuuluu?",
			ScenarioGreetTranslation: "Hi! How are you?",
			ScenarioAskMessage:       "Voitko auttaa minua?",
			ScenarioAskTranslation:   "Can you help me?",
			ScenarioHintWouldLike:    "[I would like... in Finnish]",
			ScenarioHintHelp:         "[Can you help me... in Finnish]",
			ScenarioHintLookingFor:   "[I'm looking for... in Finnish]",
			ScenarioHintNeed:         "[I need... in Finnish]",
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
		},
	},
	"sv": {
		Code: "sv",
		Display: DisplayCapability{
			DisplayNameEn:           "Swedish",
			CountryContext:          "Sweden",
			CapitalScene:            "Stockholm subway platform on a bright weekday morning.",
			NativeScriptHashtags:    []string{"#svenska"},
			DailyChallengeThemeName: "Vardag",
		},
		Morphology: MorphologyCapability{
			PrimaryBackend:       "swedish_morphology",
			LocalFallbackModule:  "swedish_morphology",
			HasParadigmGenerator: true,
			SpacyPipeline:        "sv_core_news_sm",
			ExclusiveCases:       []string{}, // none unique to Swedish
		},
		TTS: TTSCapability{
			// Pronunciation prose is sourced from env at runtime
			// (settings.OPENAI_TTS_SV_INSTRUCTIONS).
			PronunciationInstructions: "",
			PreferredVoiceID:          "",
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
		},
		Prompts: PromptCapability{
			ScenarioGreetMessage:     "Hej! Hur mår du?",
			ScenarioGreetTranslation:    "Hi! How are you?",
			ScenarioAskMessage:          "Kan du hjälpa mig?",
			ScenarioAskTranslation:      "Can you help me?",
			ScenarioHintWouldLike:       "[I would like... in Swedish]",
			ScenarioHintHelp:            "[Can you help me... in Swedish]",
			ScenarioHintLookingFor:      "[I'm looking for... in Swedish]",
			ScenarioHintNeed:            "[I need... in Swedish]",
			PoliteExamples:              "tack, ursäkta, hej",
			OfflineTranslationFallbacks: map[string]string{}, // no Swedish offline dictionary yet
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
