// Package-level endpoint-name constants for the kielo-cms HTTP-shaped
// writer endpoints that engine + ingest services use to persist
// cms_<lang>.* and cms.* state via Pub-Sub-less synchronous RPC
// (instead of direct schema-qualified SQL).
//
// Sibling typed-vocabulary SoT modules in this package:
//   - eventtype.go             (ADR-011 spine; UserActionEnvelope)
//   - outboxeventtype.go       (Sweep SSS-C; outbox-drainer events)
//   - publisheventtype.go      (Sweep IIII; direct-publish events)
//   - cmswriterendpoint.go     (THIS FILE; Sweep XXXXX; ADR-012 §D2.3 Phase 4)
//
// Background (Sweep XXXXX-A, 2026-06-02):
//   Pre-XXXXX the kielolearn-engine wrote directly to kielo-cms-owned
//   schemas (`cms_<lang>.base_words`, `cms_<lang>.dictionary_senses`,
//   `cms_<lang>.dictionary_enrichments`, `cms_<lang>.word_forms`,
//   `cms_<lang>.grammar_concepts`). `scripts/check_schema_ownership.py`
//   carried this as `"cms"` in the engine's OWNED_SCHEMAS with the
//   comment "writes pending ADR-012 Phase 4 (D2.3 forbids)". 19 sites
//   audit-counted across 8 files; classified into 4 invariant classes
//   (simple-column UPDATE, atomic-pair UPDATE+UPSERT, conditional-NULL
//   data-quality repair, batch embedding write).
//
//   Sweep XXXXX is a 4-round arc closing Phase 4:
//     XXXXX-A — pattern establishment: 5 sites cut over via 4 endpoints
//     XXXXX-B — atomic-pair composite endpoint: 4 user-path sites
//     XXXXX-C — embedding endpoints (single + batch): 4 worker-loop sites
//     XXXXX-D — large-payload upserts + topic_list INSERT: 4 sites
//
//   After XXXXX-D the engine's OWNED_SCHEMAS drops `cms`/`cms_fi`/`cms_sv`
//   entirely; the schema-ownership lint gate goes hard-fail for any
//   future engine SQL touching cms_<lang>.*.
//
// Vocabulary discipline (Sweep WW typed-constant SoT):
//   Every cms-side writer endpoint declares a CMSWriterEndpoint
//   constant whose wire-string form encodes (resource, operation,
//   version) — e.g. "base_word.audio.update.v1". Engine clients
//   pass the typed alias when constructing requests; CMS handlers
//   register routes under the matching URL template. A static gate
//   in `tests/contract/cms_writer_endpoint_vocabulary_contract_test.go`
//   enforces (a) every constant appears in the AllCMSWriterEndpoints
//   slice, (b) wire strings are unique, (c) every consumed endpoint
//   in engine source maps to a known constant — vocabulary drift is
//   compile-time impossible at the producer side.
//
// Distinct from EventType / OutboxEventType / PublishEventType:
//   those three vocabularies are Pub/Sub message attributes. This
//   one is an HTTP endpoint identifier. The string namespaces are
//   disjoint (.v1 suffix on both shapes is coincidental).

package events

// CMSWriterEndpoint is the typed alias engine clients pass into the
// kielo-shared cms_writers HTTP client when constructing requests
// against kielo-cms. The wire string follows the
// "<resource>.<operation>.v<N>" naming pattern so the version can be
// bumped without renaming the resource.
//
// HTTP URL templates are NOT carried by this constant — the URL is
// derived per-endpoint in the client module. The constant identifies
// the SoT (cms-side handler + engine-side caller pair) for the
// contract gate.
type CMSWriterEndpoint string

// String returns the wire string for log / metric / span attribute
// binding without an explicit conversion at the call site.
func (c CMSWriterEndpoint) String() string {
	return string(c)
}

// Sweep XXXXX-A pattern-establishment endpoints. These cover the 5
// smallest-blast-radius sites and validate the canonical Pattern-D
// template (HTTP-shaped projection writer, vocabulary SoT, contract
// gate, engine client base, cross-language parity test).
const (
	// CMSWriterGrammarConceptExamplesUpdate fires on the engine's
	// grammar_example_enrichment.py:_store_examples — overwrites the
	// example_sentences JSONB column on cms_<lang>.grammar_concepts.
	// Idempotent; deterministic by grammar_concept_id; safe on retry.
	// Engine consumer: grammar_example_enrichment.py site 16.
	// CMS handler: PATCH /internal/klearn/grammar-concepts/:grammar_concept_id/examples
	CMSWriterGrammarConceptExamplesUpdate CMSWriterEndpoint = "grammar_concept.examples.update.v1"

	// CMSWriterBaseWordAudioUpdate fires on the engine's
	// tts_service.py:_update_base_word_audio — sets the
	// audio_pronunciation_url on cms_<lang>.base_words. The
	// `overwrite` body field toggles between unconditional update
	// (overwrite=true) and conditional-on-blank (overwrite=false,
	// for cache-hit replay).
	// Engine consumers: tts_service.py sites 14 + 15.
	// CMS handler: PATCH /internal/klearn/base-words/:base_word_id/audio
	CMSWriterBaseWordAudioUpdate CMSWriterEndpoint = "base_word.audio.update.v1"

	// CMSWriterBaseWordMeaningNull fires on the engine's
	// data_quality/base_word_meaning_checker.py:repair — conditional
	// NULL'ing of the meaning column when the row still holds the
	// flagged value. The `if_current_value` query param carries the
	// optimistic-concurrency guard; server returns
	// {action: "updated" | "noop"} based on rowcount.
	// Engine consumer: base_word_meaning_checker.py site 12.
	// CMS handler: DELETE /internal/klearn/base-words/:base_word_id/meaning?if_current_value=<v>
	CMSWriterBaseWordMeaningNull CMSWriterEndpoint = "base_word.meaning.null.v1"

	// CMSWriterDictionarySenseTranslationNull fires on the engine's
	// data_quality/sense_translation_checker.py:repair — same shape
	// as BaseWordMeaningNull but against
	// cms_<lang>.dictionary_senses.translation. The conditional-NULL
	// is keyed by (base_word_id, language_code, sense_order); the
	// `if_current_value` query param guards the optimistic update.
	// Engine consumer: sense_translation_checker.py site 11.
	// CMS handler: DELETE /internal/klearn/base-words/:base_word_id/senses/:sense_order/translation?if_current_value=<v>
	CMSWriterDictionarySenseTranslationNull CMSWriterEndpoint = "dictionary_sense.translation.null.v1"

	// Sweep XXXXX-B (2026-06-02) — atomic-pair composite endpoint
	// covering the dictionary-enrichment hot path. Single cms-side
	// tx UPDATEs base_words.meaning + UPSERTs N dictionary_senses
	// rows atomically. Preserves the Sweep BBB tx-split invariant
	// (translation writes commit together BEFORE embedding writes).
	//
	// Request body shape:
	//   {
	//     "meaning": "...",                  // required string
	//     "only_if_blank": false,            // optional bool — site 9 back-fill flag
	//     "senses": [{                       // optional list
	//       "language_code": "en",
	//       "sense_order": 1,
	//       "translation": "...",
	//       "tags": ["gemini_one_shot", "confidence:0.85", "lemma:x", "pos:noun"]
	//     }]
	//   }
	//
	// Server response:
	//   {
	//     "meaning_action": "updated" | "noop",  // noop when only_if_blank=true + value already set
	//     "senses_upserted": <int>
	//   }
	//
	// Engine consumers:
	//   - internal_router.py:enrich_words_by_ids sites 2+4 (DDD primary), 3+4 (opus-mt fallback)
	//   - internal_router.py:enrich_words_with_translations sites 6+7 (EEE-Gemini)
	//   - dictionary_enrichment.py:enrich_dictionary_entries site 9 (back-fill, senses=[])
	// CMS handler: POST /internal/klearn/base-words/:base_word_id/translation
	CMSWriterBaseWordTranslationUpsert CMSWriterEndpoint = "base_word.translation.upsert.v1"
)

// AllCMSWriterEndpoints is the canonical iteration order for the
// contract-test parity scan + future enumeration helpers. New
// endpoints added in XXXXX-B/C/D must be appended in declaration
// order; the contract test asserts the slice cardinality matches the
// number of declared constants (no typed constant can be silently
// orphaned from the iteration order).
var AllCMSWriterEndpoints = []CMSWriterEndpoint{
	// XXXXX-A pattern-establishment block:
	CMSWriterGrammarConceptExamplesUpdate,
	CMSWriterBaseWordAudioUpdate,
	CMSWriterBaseWordMeaningNull,
	CMSWriterDictionarySenseTranslationNull,
	// XXXXX-B atomic-pair composite block:
	CMSWriterBaseWordTranslationUpsert,
	// XXXXX-C/D blocks queued; will append here as they ship.
}

// IsKnownCMSWriterEndpoint returns true when wire is a registered
// endpoint constant. Used by the contract gate + future client
// validators to reject typo'd endpoint references.
func IsKnownCMSWriterEndpoint(wire string) bool {
	for _, e := range AllCMSWriterEndpoints {
		if string(e) == wire {
			return true
		}
	}
	return false
}
