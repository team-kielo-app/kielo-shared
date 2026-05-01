package pagination

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// CursorPage is the canonical mobile-facing cursor pagination shape.
// Use for endpoints intended for mobile clients.
type CursorPage[T any] struct {
	Items       []T    `json:"items"`
	NextPageKey string `json:"next_page_key,omitempty"`
}

// EncodeOffsetCursor returns an opaque b64 cursor encoding an integer offset.
// Use for offset-based stable iteration when the underlying query is offset-driven.
// Returns an empty string when offset <= 0 (no further pages / at start).
func EncodeOffsetCursor(offset int) string {
	if offset <= 0 {
		return ""
	}
	raw := fmt.Sprintf("o:%d", offset)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeOffsetCursor parses an opaque cursor back to an integer offset.
// Returns 0 (and no error) for empty cursor.
// Accepts both the canonical "o:N" b64 form and a bare integer string for
// back-compat with handlers that previously emitted plain offsets.
func DecodeOffsetCursor(cursor string) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(cursor); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("invalid cursor: negative offset")
		}
		return n, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor: %w", err)
	}
	s := string(decoded)
	if !strings.HasPrefix(s, "o:") {
		return 0, fmt.Errorf("invalid cursor: missing offset prefix")
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "o:"))
	if err != nil {
		return 0, fmt.Errorf("invalid cursor: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid cursor: negative offset")
	}
	return n, nil
}
