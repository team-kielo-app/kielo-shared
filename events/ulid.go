package events

import (
	"crypto/rand"
	"fmt"
	"time"
)

// crockfordAlphabet is Crockford's base32 — excludes I, L, O, U to
// avoid ambiguity with 1, 0, V. This matches the ULID spec and the
// kielo-events validator (kielo-events/internal/validate/event_id.go).
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a fresh 26-char Crockford-base32 ULID:
//
//	[0:10]  = 48-bit Unix milliseconds (big-endian, encoded high-to-low)
//	[10:26] = 80 bits of crypto/rand entropy
//
// The result is lexicographically sortable by timestamp — two ULIDs
// minted in the same millisecond on different machines won't collide
// at the byte level until the 80-bit randomness collides (1-in-2^80,
// astronomically improbable).
//
// crypto/rand failure is fatal: every caller is on a write path that
// depends on idempotency, and silently returning a zero/duplicate
// ULID would break end-to-end exactly-once. Failure here means the
// kernel entropy source is broken — the right call is to crash the
// process so orchestration reschedules.
func NewULID() string {
	return NewULIDFromTime(time.Now())
}

// NewULIDFromTime is NewULID with an explicit timestamp source. Used
// by tests to assert lexicographic ordering and by deterministic
// replay paths that need a stable encoding.
func NewULIDFromTime(now time.Time) string {
	ms := uint64(now.UnixMilli())

	var randBytes [10]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		// See doc comment — entropy failure is non-recoverable.
		panic(fmt.Sprintf("events.NewULID: crypto/rand.Read failed: %v", err))
	}

	// Encode 48-bit ms timestamp into 10 chars + 80-bit randomness
	// into 16 chars. The encoding stamps bits high-to-low across the
	// 26-char output so lexicographic sort == numeric sort by ts.
	var out [26]byte

	// Timestamp: bits 47..0 → chars 0..9 (5 bits per char, MSB first).
	out[0] = crockfordAlphabet[(ms>>45)&0x1F]
	out[1] = crockfordAlphabet[(ms>>40)&0x1F]
	out[2] = crockfordAlphabet[(ms>>35)&0x1F]
	out[3] = crockfordAlphabet[(ms>>30)&0x1F]
	out[4] = crockfordAlphabet[(ms>>25)&0x1F]
	out[5] = crockfordAlphabet[(ms>>20)&0x1F]
	out[6] = crockfordAlphabet[(ms>>15)&0x1F]
	out[7] = crockfordAlphabet[(ms>>10)&0x1F]
	out[8] = crockfordAlphabet[(ms>>5)&0x1F]
	out[9] = crockfordAlphabet[ms&0x1F]

	// Randomness: 80 bits across chars 10..25 (16 chars × 5 bits = 80).
	// Read 5-bit groups from the 10-byte buffer.
	out[10] = crockfordAlphabet[(randBytes[0]>>3)&0x1F]
	out[11] = crockfordAlphabet[((randBytes[0]&0x07)<<2)|((randBytes[1]>>6)&0x03)]
	out[12] = crockfordAlphabet[(randBytes[1]>>1)&0x1F]
	out[13] = crockfordAlphabet[((randBytes[1]&0x01)<<4)|((randBytes[2]>>4)&0x0F)]
	out[14] = crockfordAlphabet[((randBytes[2]&0x0F)<<1)|((randBytes[3]>>7)&0x01)]
	out[15] = crockfordAlphabet[(randBytes[3]>>2)&0x1F]
	out[16] = crockfordAlphabet[((randBytes[3]&0x03)<<3)|((randBytes[4]>>5)&0x07)]
	out[17] = crockfordAlphabet[randBytes[4]&0x1F]
	out[18] = crockfordAlphabet[(randBytes[5]>>3)&0x1F]
	out[19] = crockfordAlphabet[((randBytes[5]&0x07)<<2)|((randBytes[6]>>6)&0x03)]
	out[20] = crockfordAlphabet[(randBytes[6]>>1)&0x1F]
	out[21] = crockfordAlphabet[((randBytes[6]&0x01)<<4)|((randBytes[7]>>4)&0x0F)]
	out[22] = crockfordAlphabet[((randBytes[7]&0x0F)<<1)|((randBytes[8]>>7)&0x01)]
	out[23] = crockfordAlphabet[(randBytes[8]>>2)&0x1F]
	out[24] = crockfordAlphabet[((randBytes[8]&0x03)<<3)|((randBytes[9]>>5)&0x07)]
	out[25] = crockfordAlphabet[randBytes[9]&0x1F]

	return string(out[:])
}

// ULIDLength is the canonical length of a Crockford-base32 ULID.
// Convenience export so callers don't have to magic-number 26.
const ULIDLength = 26
