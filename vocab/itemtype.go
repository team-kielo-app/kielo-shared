// Package vocab holds closed-vocabulary typed aliases shared across
// kielo services. Producers reference the typed constants instead of
// raw string literals so a typo or a case-drift can't sneak past the
// compiler.
//
// Adding a new constant to one of these vocabularies:
//
//  1. Update the canonical doc (this file's per-vocab comment + the
//     relevant ADR if there is one).
//  2. Add the constant here, paired with its all-canonical-cases entry
//     in the AllItemTypes / AllSaveStatuses / etc. slice.
//  3. Run tests/contract/vocab_contract_test.go to verify the
//     constants stay normalized + a producer hasn't snuck in a literal.
package vocab

// ItemType is the closed vocabulary identifying which kind of
// learnable item an event / record / API field refers to.
//
// Values are PascalCase to match the Go-side model type names (BaseWord,
// GrammarConcept, etc) — producers MUST use this casing exactly so the
// search-by-item-type switches across services agree.
//
// Drift caught: tests/e2e-full-pipeline/swedish_pipeline_e2e_test.go
// once emitted "base_word" (snake) at line 328 — silently fell through
// every case "BaseWord" switch on the consumer side. Pinning the values
// via this typed alias prevents recurrence.
type ItemType string

const (
	ItemTypeBaseWord       ItemType = "BaseWord"
	ItemTypeGrammarConcept ItemType = "GrammarConcept"
	ItemTypeConceptHub     ItemType = "ConceptHub"
	ItemTypeRoadmapLesson  ItemType = "RoadmapLesson"
	ItemTypeTopicList      ItemType = "TopicList"
	ItemTypeArticle        ItemType = "Article"
	ItemTypeVideo          ItemType = "Video"
)

// AllItemTypes is the closed set. Used by the contract test that pins
// the producer / consumer vocab against this list.
var AllItemTypes = []ItemType{
	ItemTypeBaseWord,
	ItemTypeGrammarConcept,
	ItemTypeConceptHub,
	ItemTypeRoadmapLesson,
	ItemTypeTopicList,
	ItemTypeArticle,
	ItemTypeVideo,
}

// IsValidItemType returns true when s exactly matches a known constant.
// Producers parsing inbound user input should use this to validate
// before passing to a typed-API surface.
func IsValidItemType(s string) bool {
	for _, t := range AllItemTypes {
		if string(t) == s {
			return true
		}
	}
	return false
}
