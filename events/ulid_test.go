package events

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewULID_Length(t *testing.T) {
	id := NewULID()
	assert.Len(t, id, ULIDLength)
}

func TestNewULID_CrockfordAlphabetOnly(t *testing.T) {
	id := NewULID()
	for i := 0; i < len(id); i++ {
		assert.True(t, strings.ContainsRune(crockfordAlphabet, rune(id[i])),
			"ULID char at index %d (%c) not in Crockford alphabet", i, id[i])
	}
}

func TestNewULID_NoForbiddenChars(t *testing.T) {
	// I, L, O, U MUST never appear (Crockford explicitly excludes).
	for i := 0; i < 1000; i++ {
		id := NewULID()
		for _, ch := range []byte("ILOU") {
			assert.NotContains(t, id, string(ch),
				"ULID %s contains forbidden char %c", id, ch)
		}
	}
}

func TestNewULID_LexicographicallySorts(t *testing.T) {
	// Two ULIDs minted 10ms apart MUST sort by their timestamps.
	t0 := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	id1 := NewULIDFromTime(t0)
	id2 := NewULIDFromTime(t0.Add(10 * time.Millisecond))
	assert.Less(t, id1, id2,
		"ULID from later timestamp must sort after earlier (got %s, %s)", id1, id2)
}

func TestNewULID_TimestampEncoding(t *testing.T) {
	// Same timestamp → same 10-char prefix (only the randomness
	// suffix differs). Pin this to catch the bit-shift logic.
	t0 := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	id1 := NewULIDFromTime(t0)
	id2 := NewULIDFromTime(t0)
	assert.Equal(t, id1[:10], id2[:10],
		"ULIDs minted at the same instant must share the 10-char timestamp prefix")
	assert.NotEqual(t, id1[10:], id2[10:],
		"ULIDs minted at the same instant must NOT share the 16-char randomness suffix")
}

func TestNewULID_HighUniqueness(t *testing.T) {
	// 10k ULIDs from the same millisecond MUST be all distinct (80
	// bits of randomness; collision probability is ~2^-60).
	t0 := time.Now()
	seen := make(map[string]struct{}, 10000)
	for i := 0; i < 10000; i++ {
		id := NewULIDFromTime(t0)
		_, dup := seen[id]
		require.False(t, dup, "duplicate ULID at iteration %d: %s", i, id)
		seen[id] = struct{}{}
	}
}
