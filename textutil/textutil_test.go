package textutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for the cross-service string-munging helpers. These are used
// by dozens of handlers to fold multi-source strings (request body >
// query param > default), dereference optional JSON fields, and pull
// language codes out of heterogeneous metadata maps. Small bugs here
// silently propagate across the fleet — e.g. a nil-pointer return
// bypassing trim, or "<nil>" leaking through StringFromMap into a
// learner's UI.

func TestFirstNonEmpty_ReturnsFirstTrimmedValue(t *testing.T) {
	assert.Equal(t, "hello", FirstNonEmpty("hello"))
	assert.Equal(t, "hello", FirstNonEmpty("", "hello"))
	assert.Equal(t, "hello", FirstNonEmpty("", "", "hello", "world"))
}

func TestFirstNonEmpty_TrimsWhitespace(t *testing.T) {
	// A string that is ONLY whitespace counts as empty and gets skipped.
	// This is the load-bearing invariant — without it a trailing space
	// in a query param would win over a fully-populated request body.
	assert.Equal(t, "hello", FirstNonEmpty("   ", "hello"))
	assert.Equal(t, "hello", FirstNonEmpty("\t\n", " hello "))
}

func TestFirstNonEmpty_AllEmpty(t *testing.T) {
	assert.Equal(t, "", FirstNonEmpty())
	assert.Equal(t, "", FirstNonEmpty(""))
	assert.Equal(t, "", FirstNonEmpty("", "  ", "\t"))
}

func TestFirstNonEmptyPtr_ReturnsPointerToTrimmedCopy(t *testing.T) {
	a := ""
	b := "  swedish  "
	c := "english"
	got := FirstNonEmptyPtr(&a, &b, &c)
	assert.NotNil(t, got)
	assert.Equal(t, "swedish", *got)
}

func TestFirstNonEmptyPtr_SkipsNils(t *testing.T) {
	// nil interleaved with empties must be traversed, not crashed.
	b := "vi"
	got := FirstNonEmptyPtr(nil, nil, &b)
	assert.NotNil(t, got)
	assert.Equal(t, "vi", *got)
}

func TestFirstNonEmptyPtr_DoesNotReturnLoopScopedPointer(t *testing.T) {
	// The implementation copies the trimmed string into a new local
	// var before taking its address. If a refactor returned &trimmed
	// directly the pointer would technically still be valid (Go
	// escape-analyzes to heap), but returning &v would alias the
	// caller's input — dangerous when the caller mutates afterward.
	// Pin the invariant: caller mutation must NOT affect our return.
	b := "original"
	got := FirstNonEmptyPtr(&b)
	assert.NotNil(t, got)
	assert.Equal(t, "original", *got)
	// Mutate the caller's input AFTER the call.
	b = "mutated"
	// Our return must still show the original trimmed value.
	assert.Equal(t, "original", *got, "returned pointer must not alias caller input")
}

func TestFirstNonEmptyPtr_AllEmptyReturnsNil(t *testing.T) {
	assert.Nil(t, FirstNonEmptyPtr())
	empty := ""
	assert.Nil(t, FirstNonEmptyPtr(&empty))
	whitespace := "   "
	assert.Nil(t, FirstNonEmptyPtr(&whitespace, nil))
}

func TestStringValue_DereferencesOrReturnsEmpty(t *testing.T) {
	v := "hello"
	assert.Equal(t, "hello", StringValue(&v))
	assert.Equal(t, "", StringValue(nil))
}

func TestStringValue_DoesNotTrim(t *testing.T) {
	// Unlike FirstNonEmpty, StringValue is a raw dereference. It is
	// explicitly NOT a trim — callers that need trimming use the
	// other helpers. Pin this so a future "helpful" refactor doesn't
	// silently start trimming and break callers that depend on
	// preserving leading/trailing whitespace (e.g. preformatted text).
	v := "  padded  "
	assert.Equal(t, "  padded  ", StringValue(&v))
}

func TestStringPtr_ReturnsAddressOfCopy(t *testing.T) {
	got := StringPtr("hello")
	assert.NotNil(t, got)
	assert.Equal(t, "hello", *got)
}

func TestStringFromMap_ReturnsFirstNonEmptyByKeyOrder(t *testing.T) {
	// Explicit key-order precedence: callers pass "preferred" first,
	// "fallback" second. The FIRST populated key wins regardless of
	// map iteration order (which Go randomizes).
	m := map[string]any{
		"learning_language_code":  "sv",
		"language_code":           "fi", // legacy alias, should not win
	}
	assert.Equal(t, "sv", StringFromMap(m, "learning_language_code", "language_code"))
	// Swap the preferred order and the fallback wins when preferred is absent.
	assert.Equal(t, "fi", StringFromMap(map[string]any{"language_code": "fi"},
		"learning_language_code", "language_code"))
}

func TestStringFromMap_HandlesNilMap(t *testing.T) {
	// nil map without panicking — callers pass req.Metadata maps that
	// are often nil for first-time events.
	assert.Equal(t, "", StringFromMap(nil, "foo", "bar"))
}

func TestStringFromMap_SkipsNilValues(t *testing.T) {
	// A key present but with a nil interface value (e.g. from JSON
	// {"foo": null}) must be treated as absent, not as the literal
	// string "<nil>".
	m := map[string]any{
		"primary":  nil,
		"fallback": "real value",
	}
	assert.Equal(t, "real value", StringFromMap(m, "primary", "fallback"))
}

func TestStringFromMap_GuardsAgainstNilStringRender(t *testing.T) {
	// If someone put a typed nil (e.g. (*string)(nil)) into the map,
	// fmt.Sprint renders it as "<nil>". The helper explicitly filters
	// that literal so it doesn't leak into UI. Pin this contract —
	// removing the "<nil>" guard would be a silent data-quality bug.
	var typedNilPtr *string
	m := map[string]any{
		"primary":  typedNilPtr,
		"fallback": "actual",
	}
	assert.Equal(t, "actual", StringFromMap(m, "primary", "fallback"))
}

func TestStringFromMap_TrimsWhitespace(t *testing.T) {
	m := map[string]any{
		"key": "  padded  ",
	}
	assert.Equal(t, "padded", StringFromMap(m, "key"))
}

func TestStringFromMap_SupportsNonStringValues(t *testing.T) {
	// fmt.Sprint handles int/bool/etc. — useful for Pub/Sub attribute
	// maps where everything gets JSON-parsed into any.
	m := map[string]any{
		"count":    42,
		"verified": true,
	}
	assert.Equal(t, "42", StringFromMap(m, "count"))
	assert.Equal(t, "true", StringFromMap(m, "verified"))
}

func TestStringFromMap_AllMissingReturnsEmpty(t *testing.T) {
	m := map[string]any{"other": "x"}
	assert.Equal(t, "", StringFromMap(m, "foo", "bar"))
}
