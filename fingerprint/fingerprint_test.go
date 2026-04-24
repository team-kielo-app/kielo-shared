package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for the SHA-256 part-fingerprint helper used for cache-key
// composition (e.g. kielo-convo's conversation-hint cache). Three
// load-bearing invariants must hold:
//  1. **Stability** — the same inputs always produce the same hash.
//  2. **Separator isolation** — `Parts("ab", "c")` must NOT collide
//     with `Parts("a", "bc")`. The current implementation writes a
//     NUL byte between parts to enforce this.
//  3. **Trim normalization** — leading/trailing whitespace must not
//     change the fingerprint, so a message with a trailing "\n" from
//     JSON parsing lands in the same cache bucket as the same message
//     without it.
//
// A silent regression on any of these causes either cache poisoning
// (two distinct inputs sharing a cache slot) or cache fragmentation
// (identical inputs missing the cache).

func TestStringParts_IsStableAcrossCalls(t *testing.T) {
	a := StringParts("user:hello", "assistant:hi")
	b := StringParts("user:hello", "assistant:hi")
	assert.Equal(t, a, b, "identical inputs must produce identical fingerprints")
}

func TestStringParts_ProducesHexEncodedSha256(t *testing.T) {
	// SHA-256 → 32 bytes → 64 hex chars. Pin the length so a future
	// swap to a shorter/longer hash algorithm is caught (cache keys
	// persisted in Redis would otherwise start mixing lengths).
	got := StringParts("anything")
	assert.Len(t, got, 64, "fingerprint must be 64-char SHA-256 hex")
	// Lowercase hex only — no accidental base64 migration.
	for _, r := range got {
		assert.True(t,
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'),
			"fingerprint must be lowercase hex, got %q", r)
	}
}

func TestStringParts_DifferentPartitioningsDoNotCollide(t *testing.T) {
	// The NUL separator prevents this collision. If someone "optimizes"
	// by concatenating without separators, the two lines below would
	// produce the same fingerprint — a silent cache-key collision
	// that's impossible to debug from outside.
	ab_c := StringParts("ab", "c")
	a_bc := StringParts("a", "bc")
	assert.NotEqual(t, ab_c, a_bc,
		"parts with different boundaries must not collide")
}

func TestStringParts_DifferentInputsProduceDifferentFingerprints(t *testing.T) {
	a := StringParts("user:hello")
	b := StringParts("user:hi")
	assert.NotEqual(t, a, b)
}

func TestStringParts_TrimsLeadingAndTrailingWhitespace(t *testing.T) {
	// Whitespace-equivalent inputs share a fingerprint. This is the
	// reason the helper exists — JSON-parsed strings often carry
	// trailing newlines that would otherwise fragment the cache.
	canonical := StringParts("user:hello", "assistant:hi")
	padded := StringParts("  user:hello\n", "\tassistant:hi ")
	assert.Equal(t, canonical, padded,
		"whitespace around each part must not change the fingerprint")
}

func TestStringParts_InternalWhitespacePreserved(t *testing.T) {
	// Trimming is ONLY at the ends — internal whitespace is
	// load-bearing (e.g. it distinguishes "Hello world" from
	// "Helloworld") and must be preserved.
	with := StringParts("Hello world")
	without := StringParts("Helloworld")
	assert.NotEqual(t, with, without)
}

func TestStringParts_EmptyInputs(t *testing.T) {
	// Zero parts, one empty part, two empty parts — all distinct
	// because each still writes a NUL separator to the hasher.
	zero := StringParts()
	oneEmpty := StringParts("")
	twoEmpty := StringParts("", "")
	assert.NotEqual(t, zero, oneEmpty)
	assert.NotEqual(t, oneEmpty, twoEmpty)
	assert.Len(t, zero, 64)
}

func TestStringParts_WhitespaceOnlyPartIsEquivalentToEmpty(t *testing.T) {
	// A part that's ONLY whitespace trims to "" and thus matches the
	// empty-part fingerprint. Protects a common upstream footgun
	// where an optional field arrives as "   " instead of "" or
	// missing, and should still land in the same cache slot.
	emptyPart := StringParts("")
	whitespacePart := StringParts("   ")
	assert.Equal(t, emptyPart, whitespacePart)
}
