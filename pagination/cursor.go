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
	// Meta carries page-level hints that are not items. Omitted entirely when
	// nothing applies, so existing consumers see an unchanged envelope.
	Meta *CursorPageMeta `json:"meta,omitempty"`
}

// CursorPageMeta is the optional page-level hint block of a CursorPage.
type CursorPageMeta struct {
	// LocalizationPending counts items whose learner-facing text was served
	// in the canonical language because its translation is still being
	// produced in the background (serve-source-now / fill-later reads). A
	// client that shows this page can refetch once shortly after to pick the
	// translations up; zero or absent means the page is fully localized.
	LocalizationPending int `json:"localization_pending,omitempty"`
}

// NewCursorPage builds a CursorPage[T] from a slice and a possibly-nil
// next-page cursor. It exists so that handlers translating legacy
// `{<thing>, next_page_key *string}` paginated bodies into the canonical
// `{items, next_page_key string}` envelope share ONE adapter — instead
// of each handler hand-rolling the nil-check + nil-slice defense.
//
// The nil-slice defense matters: encoding/json renders `nil` slices as
// `null`, which JS clients then choke on when they call `.map`. We
// normalize to an empty array so the canonical wire shape is
// `{"items": [], ...}` regardless of upstream nil-ness.
//
// Usage:
//
//	resp := h.service.FindArticles(ctx, opts)  // *PaginatedArticleVersionsResponse
//	return c.JSON(http.StatusOK, pagination.NewCursorPage(resp.Articles, resp.NextPageKey))
func NewCursorPage[T any](items []T, nextPageKey *string) CursorPage[T] {
	if items == nil {
		items = []T{}
	}
	key := ""
	if nextPageKey != nil {
		key = *nextPageKey
	}
	return CursorPage[T]{
		Items:       items,
		NextPageKey: key,
	}
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
