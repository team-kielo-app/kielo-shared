package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// StringParts returns a stable SHA-256 hex fingerprint for the provided parts.
// Empty and surrounding whitespace are normalized so equivalent inputs produce
// the same fingerprint.
func StringParts(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		normalized := strings.TrimSpace(part)
		_, _ = h.Write([]byte(normalized))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
