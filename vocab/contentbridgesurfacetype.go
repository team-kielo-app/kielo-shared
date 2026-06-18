// Package vocab — Content Bridge Arc 1 (2026-06-07)
//
// ContentBridgeSurfaceType typed-vocab SoT for the Content Bridge
// cross-feature reverse-index. 15th instance of the typed-vocab SoT
// pattern (alongside achievement.go, itemtype.go, scenariosourcetype.go,
// pushkey.go, emailsubjectkey.go, kielo-shared/userlang/sources.go,
// kielo-shared/userlang/grantsource.go, kielo-shared/errors,
// kielo-shared/events/{cmswriterendpoint,outboxeventtype,publisheventtype,
// behavioral,useraction,notificationcreated}.go).
//
// Background:
//
// The Content Bridge answers the question "given (item_type, item_id,
// user_id, language), where else has this learner encountered this
// word or grammar concept across Kielo's content surfaces?"
//
// Four surface types span the answer space. Each is owned by a
// different service:
//
//   - "article"          — kielo-content-service reads from
//     cms_<lang>.occurrences (source_type='article').
//     Populated by kielo-ingest-processor at
//     article-publish time. Production-ready;
//     6,575 rows in cms_fi as of Arc 1 ship.
//
//   - "video_caption"    — kielo-content-service reads from
//     cms_<lang>.occurrences (source_type='video').
//     Populated by kielo-ingest-processor video
//     adapter at KTV-processed time. Note: a
//     parallel writer also populates
//     cms_<lang>.kielotv_mindmaps.graph; canonical
//     source for the Bridge is occurrences (see
//     ADR §5 Drive-by + §9 Open question 2).
//
//   - "scenario"         — kielo-convo reads from a NEW per-language
//     junction (planned: convo.scenario_item_references
//     OR users_conversations.scenario_item_references
//     pending the convo schema rename). Empty in
//     Arc 1; producer wires in Arc 3.
//
//   - "exercise_prompt"  — kielolearn-engine reads from a NEW per-lang
//     junction klearn_<lang>.exercise_item_references.
//     Empty in Arc 1; producer wires in Arc 2.
//
// Arc-1 contract: the reader endpoint at
// GET /internal/api/v3/content-bridge/items/{item_id}/surfaces
// accepts a comma-separated ?surface_type=... filter taking these wire
// strings. Empty results for scenario + exercise_prompt are expected
// until Arcs 2+3 populate.
//
// Adding a new ContentBridgeSurfaceType value:
//
//  1. Add the constant here with the canonical wire string.
//  2. Extend AllContentBridgeSurfaceTypes for iteration.
//  3. Add a sibling constant to kielo_shared/vocab/content_bridge_surface_type.py.
//  4. Wire the producer + reader for the new surface.
//  5. Update the contract tests' required-set in
//     tests/contract/content_bridge_surface_type_vocabulary_contract_test.go.
//
// The 3 contract tests enforce parity:
//
//	(a) Producer-side closed-set scan ✓ TestContentBridgeSurfaceTypeNoStaleLiteralsInProducer
//	(b) Go↔Python parity              ✓ TestContentBridgeSurfaceTypeGoPythonParity
//	(c) SoT cardinality + canonical   ✓ TestContentBridgeSurfaceTypeSoTNonEmpty
//
// (No DB CHECK constraint mirror — the surface type is a query-param
// vocabulary, not a column value. The closed-set discipline lives at
// the application boundary via IsKnownContentBridgeSurfaceType.)
package vocab

// ContentBridgeSurfaceType is the typed alias for the canonical
// content-surface vocabulary used by the Bridge's wire shape
// (query param + response field).
//
// Wire format is a string so request URLs and JSON responses stay
// stable across schema migrations; this Go type narrows the
// producer-side surface (reader endpoint, client SDK, contract test)
// so a stray literal can't be silently accepted.
type ContentBridgeSurfaceType string

// String returns the wire string. Allows the typed constant to be
// used directly in URL building, log fields, and JSON marshaling
// without an explicit conversion at every call site.
func (s ContentBridgeSurfaceType) String() string {
	return string(s)
}

// Production-ready surface types (2 — populated end-to-end in Arc 1).
const (
	// SurfaceArticle: news article paragraphs. Reader reads
	// cms_<lang>.occurrences WHERE source_type='article'. The
	// surface_id is the content_version_id; paragraph_id +
	// sentence_text + original_token_phrase carry the grounding
	// snippet.
	SurfaceArticle ContentBridgeSurfaceType = "article"

	// SurfaceVideoCaption: KTV video caption cues. Reader reads
	// cms_<lang>.occurrences WHERE source_type='video'. The
	// surface_id is the content_version_id; caption_index +
	// timestamp_start + sentence_text carry the grounding snippet
	// + seek target.
	SurfaceVideoCaption ContentBridgeSurfaceType = "video_caption"
)

// Producer-pending surface types (2 — empty junction tables in Arc 1;
// readers return [] until producers wire up).
const (
	// SurfaceScenario: convo scenario turns + hints. Empty in
	// Arc 1; producer wired in Arc 3 (sub-recon-driven choice:
	// post-session correction extraction OR LLM batch annotation
	// OR author-time annotation).
	SurfaceScenario ContentBridgeSurfaceType = "scenario"

	// SurfaceExercisePrompt: kielolearn-engine generated exercise
	// prompts. Empty in Arc 1; producer wired in Arc 2 (LLM
	// emit-time annotation at structured_output.py persist point).
	SurfaceExercisePrompt ContentBridgeSurfaceType = "exercise_prompt"
)

// AllContentBridgeSurfaceTypes is the canonical iteration order.
// Used by:
//   - The reader endpoint's default surface filter (when no
//     ?surface_type=... param is supplied).
//   - The Go↔Python parity contract test (asserts every Python
//     mirror constant has a Go sibling and vice-versa).
//   - The producer-scan contract test (asserts no production code
//     emits a wire string outside this set).
var AllContentBridgeSurfaceTypes = []ContentBridgeSurfaceType{
	SurfaceArticle,
	SurfaceVideoCaption,
	SurfaceScenario,
	SurfaceExercisePrompt,
}

// IsKnownContentBridgeSurfaceType returns true when s is one of the
// canonical values. Used by the reader endpoint to reject typo'd
// query-param values at the application boundary (HTTP 400) before
// they reach the SELECT planner.
func IsKnownContentBridgeSurfaceType(s ContentBridgeSurfaceType) bool {
	for _, known := range AllContentBridgeSurfaceTypes {
		if known == s {
			return true
		}
	}
	return false
}
