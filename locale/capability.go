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
	// REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
	//   * PrimaryBackend — no production consumer; morphology dispatch
	//     happens inside kielo-models with no registry lookup.
	//   * LocalFallbackModule — no production consumer; the engine's
	//     LanguageAdapter.local_morphology_provider() (slice 4b) is the
	//     actual dispatch mechanism.
	//   * HasParadigmGenerator — populated true for both fi+sv but
	//     never queried.
	// Field names retained in this comment so future audits can confirm
	// they were intentionally deleted, not accidentally lost.
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
	// NativeScriptHashtags is the curated set of native-script
	// hashtags appended to KTV captions (e.g. ["#suomi","#suomenkieli"]
	// for fi, ["#svenska"] for sv).
	NativeScriptHashtags []string
	// DefaultKtvVocabularySourceURL is the curated default URL the
	// KTV vocabulary importer uses when no req.SourceURL is supplied
	// AND no manual words list is supplied. Empty string means "no
	// default — caller must provide an explicit source URL." Phase
	// 12 slice 7: previously hard-coded as a Finnish-only constant
	// in kielo-cms/internal/services/ktv_vocabulary_importer.go.
	DefaultKtvVocabularySourceURL string
	// REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
	//   * CapitalScene — duplicated by Caption.SceneGreeting (which
	//     IS consumed by ktv_locale.go); identical strings, kept
	//     accidentally during slice 1.
	//   * DailyChallengeThemeName — populated for both fi+sv but
	//     never queried. The actual theme dispatch goes through
	//     modules/themes.DEFAULT_THEMES.localized_name() per slice 6.
}

// TTSCapability covers per-language gpt-4o-mini-tts configuration.
// Populated from §B.4.
type TTSCapability struct {
	// PronunciationInstructions is appended to the gpt-4o-mini-tts
	// `instructions` parameter to nudge the model toward correct
	// pronunciation. "" leaves the default English-trained behavior.
	PronunciationInstructions string
	// REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
	//   * PreferredVoiceID — always populated as "" for both fi+sv;
	//     no consumer ever read it.
}

// STTCapability covers per-language Whisper / Deepgram configuration.
// Currently EMPTY after Phase 12 cleanup. Re-add fields when a real
// consumer materializes.
//
// REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
//   - WhisperLanguageTag — populated as the language code itself
//     for both fi+sv; Whisper integration in kielolearn-engine
//     hard-codes the language elsewhere.
//   - DeepgramSupported — populated true for both; never queried.
type STTCapability struct {
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
	// Phase 12 slice 9 (continued): voice-pipeline STT seed words.
	// CommonWords is the per-language set of common function words
	// used by the voice pipeline to disambiguate ambiguous STT
	// outputs (e.g. "ja", "on", "se" for Finnish; "och", "är", "jag"
	// for Swedish).
	CommonWords []string
	// TerminationPhrases is the per-language set of phrases that
	// indicate the user wants to end the session (e.g. "hyvästi",
	// "näkemiin" for fi; "hej då", "adjö" for sv). The English-language
	// termination set is shared globally and added on top by the
	// voice pipeline.
	TerminationPhrases []string
}

// GrammarCapability covers per-language LLM-prompt grammar fragments
// + grammar-terminology hints used by the ingest pipeline + engine.
// Populated from scoping §B.9 + §B.11. Read primarily by the ingest
// processor's _llm_handlers.py and kielolearn-engine's dictionary
// enrichment.
type GrammarCapability struct {
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

// PhraseFrameSpec is a single phrase-frame template tuple. Phase 12
// slice 12 — populated for each POS bucket per learning language and
// read by kielolearn-engine's dictionary_enrichment to build phrase-
// frame exercise data when no LLM result is available.
//
// FrameText is the literal phrase frame containing "___" (e.g.
// "Haluan ___." for Finnish verbs).
// ExampleText contains "{term}" — replaced with the actual term at
// render time (e.g. "Haluan {term}." → "Haluan koira.").
// ExampleTranslation contains "{gloss}" — replaced with the English
// gloss at render time (e.g. "I want to {gloss}." → "I want to dog.").
type PhraseFrameSpec struct {
	FrameText          string
	ExampleText        string
	ExampleTranslation string
}

// PhraseFrameTemplates is the per-language set of phrase-frame
// templates keyed by canonical POS bucket ("verb", "adj", "adv",
// "default"). Phase 12 slice 12.
type PhraseFrameTemplates struct {
	Verb    PhraseFrameSpec
	Adj     PhraseFrameSpec
	Adv     PhraseFrameSpec
	Default PhraseFrameSpec
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
	// REMOVED 2026-05-25 (registry coverage audit, Phase 12 cleanup):
	//   * OfflineTranslationFallbacks — fi-only (10 entries) AND
	//     completely unconsumed. Migrated from kielo-cms G7 intent
	//     in slice 1 but the consumer call site was never added.
	//     Worst-of-both-worlds bloat: drifted AND unused.
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
	// HintComplexitySimple is the per-language example for simple
	// (A1-level) hint complexity, as a slash-separated list of
	// short phrases used in LLM prompts. Phase 12 slice 10.
	// e.g. for fi: `"Kiitos!" / "Haluan kahvin." / "Kyllä."`.
	HintComplexitySimple string
	// HintComplexityChallenge is the per-language example for
	// challenging (B1+) hint complexity. Phase 12 slice 10.
	HintComplexityChallenge string
	// Phase 12 slice 9 (continued): convo session-lifecycle nudges.
	// NudgeOpeners is a map keyed by session phase ("early", "mid",
	// "late") returning a list of opening phrases the agent uses
	// to nudge the user mid-session. Empty map = no nudges configured.
	NudgeOpeners map[string][]string
	// TrySayingTemplate is the per-language template the agent uses
	// to suggest a phrase. Must contain "{hint}". e.g. for fi:
	// "Kokeile vaikka: '{hint}' (Try saying: '{hint}')".
	TrySayingTemplate string
	// NoHintFallback is the per-language fallback the agent emits
	// when it has no concrete hint to offer.
	NoHintFallback string
	// WrappingUp is the per-language phrase the agent emits when
	// approaching the session time limit.
	WrappingUp string
	// PhraseFrameTemplates is the per-language POS-bucketed phrase-
	// frame templates used by kielolearn-engine's dictionary
	// enrichment when building rule-based fill-in-the-blank phrase
	// frames. Phase 12 slice 12 — drains the inline templates dict
	// from services/dictionary_enrichment.py. Empty fields = no
	// templates available for that bucket.
	PhraseFrameTemplates PhraseFrameTemplates
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
			DisplayNameEn:                 "Finnish",
			CountryContext:                "Finland",
			NativeScriptHashtags:          []string{"#suomi", "#suomenkieli"},
			DefaultKtvVocabularySourceURL: "https://uusikielemme.fi/finnish-vocabulary",
		},
		Morphology: MorphologyCapability{
			HasBaseWordLookup:    true,
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
		},
		STT: STTCapability{},
		Caption: CaptionCapability{
			SceneGreeting: "Helsinki tram stop on a bright weekday morning.",
			SceneVerb:     "Office break room before the first meeting.",
			SceneDefault:  "Kitchen at home before heading out for the day.",
		},
		Grammar: GrammarCapability{
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
			CommonWords: []string{
				"ja", "on", "se", "ei", "en", "niin", "tai", "ole", "olen", "minä", "sinä",
			},
			TerminationPhrases: []string{
				"hyvästi", "näkemiin", "kiitos ja hei", "kiitos, hei", "lopetetaan",
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
			NeverSayWords:            []string{"kielimalli", "tekoäly"},
			TerminationPhrase:        "Näkemiin",
			ThankEndPhrase:           "Kiitos käynnistä, näkemiin!",
			EncourageWords:           []string{"Hyvä!", "Hienosti!"},
			AckWords:                 []string{"Joo!", "Aivan!", "Hyvä!", "Juuri niin!"},
			BookingQuestion:          "Onko teillä varausta?",
			BookingAnswer:            "Ei hätää, voin tehdä varauksen nyt.",
			HintComplexitySimple:     `"Kiitos!" / "Haluan kahvin." / "Kyllä."`,
			HintComplexityChallenge:  `"Voisinko saada yhden cappuccinon ja pienen pullan, kiitos?" / "Haluaisin varata ajan huomiselle, jos mahdollista."`,
			NudgeOpeners: map[string][]string{
				"early": {
					"Hyvä alku! Haluatko jatkaa suomeksi?",
					"Jatketaan rauhassa. Voit vastata lyhyesti.",
				},
				"mid": {
					"Hyvin menee! Kerro vielä yhdellä lauseella.",
					"Hienosti! Mitä haluaisit sanoa seuraavaksi?",
				},
				"late": {
					"Juuri näin, jatketaan vielä hetki.",
					"Olet hyvässä vauhdissa. Kokeile vielä yksi vastaus.",
				},
			},
			TrySayingTemplate: "Kokeile vaikka: '{hint}' (Try saying: '{hint}')",
			NoHintFallback:    "Ei hätää! Voit sanoa ihan mitä vain. (No worries, say anything!)",
			WrappingUp:        "Meillä on vielä hetki aikaa. Jatketaan rauhassa!",
			PhraseFrameTemplates: PhraseFrameTemplates{
				Verb: PhraseFrameSpec{
					FrameText:          "Haluan ___.",
					ExampleText:        "Haluan {term}.",
					ExampleTranslation: "I want to {gloss}.",
				},
				Adj: PhraseFrameSpec{
					FrameText:          "Se on ___.",
					ExampleText:        "Se on {term}.",
					ExampleTranslation: "It is {gloss}.",
				},
				Adv: PhraseFrameSpec{
					FrameText:          "Tein sen ___.",
					ExampleText:        "Tein sen {term}.",
					ExampleTranslation: "I did it {gloss}.",
				},
				Default: PhraseFrameSpec{
					FrameText:          "Tämä on ___.",
					ExampleText:        "Tämä on {term}.",
					ExampleTranslation: "This is {gloss}.",
				},
			},
		},
	},
	"sv": {
		Code: "sv",
		Display: DisplayCapability{
			DisplayNameEn:                 "Swedish",
			CountryContext:                "Sweden",
			NativeScriptHashtags:          []string{"#svenska"},
			DefaultKtvVocabularySourceURL: "",
		},
		Morphology: MorphologyCapability{
			HasBaseWordLookup:    false,
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
		},
		STT: STTCapability{},
		Caption: CaptionCapability{
			SceneGreeting: "Stockholm subway platform on a bright weekday morning.",
			SceneVerb:     "Office break room before the first meeting.",
			SceneDefault:  "Kitchen at home before heading out for the day.",
		},
		Grammar: GrammarCapability{
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
			CommonWords: []string{
				"och", "är", "jag", "du", "vi", "det", "en", "ett", "har", "inte",
				"som", "på", "av", "för", "med", "men", "eller", "om", "när", "var",
			},
			TerminationPhrases: []string{
				"hej då", "adjö", "tack och hej", "vi ses", "hejdå",
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
			NeverSayWords:            []string{"språkmodell", "ai"},
			TerminationPhrase:        "Hej då",
			ThankEndPhrase:           "Tack för besöket, hej då!",
			EncourageWords:           []string{"Bra!", "Snyggt!"},
			AckWords:                 []string{"Ja!", "Precis!", "Bra!", "Just det!"},
			BookingQuestion:          "Har ni en bokning?",
			BookingAnswer:            "Inga problem, jag kan boka åt er nu.",
			HintComplexitySimple:     `"Tack!" / "Jag vill ha kaffe." / "Ja."`,
			HintComplexityChallenge:  `"Skulle jag kunna få en cappuccino och en liten bulle, tack?" / "Jag skulle vilja boka en tid till imorgon, om möjligt."`,
			NudgeOpeners: map[string][]string{
				"early": {
					"Bra start! Vill du fortsätta på svenska?",
					"Vi tar det lugnt. Du kan svara kort.",
				},
				"mid": {
					"Det går bra! Säg en mening till.",
					"Snyggt! Vad vill du säga härnäst?",
				},
				"late": {
					"Precis så, vi fortsätter en stund till.",
					"Du är på rätt väg. Försök med ett svar till.",
				},
			},
			TrySayingTemplate: "Försök säga: '{hint}' (Try saying: '{hint}')",
			NoHintFallback:    "Ingen fara! Du kan säga vad som helst. (No worries, say anything!)",
			WrappingUp:        "Vi har en stund kvar. Vi fortsätter i lugn takt!",
			PhraseFrameTemplates: PhraseFrameTemplates{
				Verb: PhraseFrameSpec{
					FrameText:          "Jag vill ___.",
					ExampleText:        "Jag vill {term}.",
					ExampleTranslation: "I want to {gloss}.",
				},
				Adj: PhraseFrameSpec{
					FrameText:          "Det är ___.",
					ExampleText:        "Det är {term}.",
					ExampleTranslation: "It is {gloss}.",
				},
				Adv: PhraseFrameSpec{
					FrameText:          "Jag gjorde det ___.",
					ExampleText:        "Jag gjorde det {term}.",
					ExampleTranslation: "I did it {gloss}.",
				},
				Default: PhraseFrameSpec{
					FrameText:          "Det här är ___.",
					ExampleText:        "Det här är {term}.",
					ExampleTranslation: "This is {gloss}.",
				},
			},
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
