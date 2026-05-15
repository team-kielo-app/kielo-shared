package pagination

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeOffsetCursor_RoundTrip(t *testing.T) {
	for _, offset := range []int{1, 10, 100, 9999, 1_000_000} {
		t.Run("", func(t *testing.T) {
			cursor := EncodeOffsetCursor(offset)
			require.NotEmpty(t, cursor)
			got, err := DecodeOffsetCursor(cursor)
			require.NoError(t, err)
			assert.Equal(t, offset, got)
		})
	}
}

func TestEncodeOffsetCursor_ZeroOrNegative(t *testing.T) {
	assert.Equal(t, "", EncodeOffsetCursor(0))
	assert.Equal(t, "", EncodeOffsetCursor(-1))
}

func TestDecodeOffsetCursor_Empty(t *testing.T) {
	got, err := DecodeOffsetCursor("")
	require.NoError(t, err)
	assert.Equal(t, 0, got)

	got, err = DecodeOffsetCursor("   ")
	require.NoError(t, err)
	assert.Equal(t, 0, got)
}

func TestDecodeOffsetCursor_BareInteger(t *testing.T) {
	got, err := DecodeOffsetCursor("42")
	require.NoError(t, err)
	assert.Equal(t, 42, got)
}

func TestDecodeOffsetCursor_Invalid(t *testing.T) {
	_, err := DecodeOffsetCursor("not-base64-and-not-int!@#")
	require.Error(t, err)
}

func TestDecodeOffsetCursor_NegativeBare(t *testing.T) {
	_, err := DecodeOffsetCursor("-1")
	require.Error(t, err)
}

func TestCursorPage_JSONShape(t *testing.T) {
	page := CursorPage[string]{
		Items:       []string{"a", "b"},
		NextPageKey: "abc",
	}
	b, err := json.Marshal(page)
	require.NoError(t, err)
	assert.JSONEq(t, `{"items":["a","b"],"next_page_key":"abc"}`, string(b))
}

func TestCursorPage_JSONShape_OmitsEmptyKey(t *testing.T) {
	page := CursorPage[string]{
		Items: []string{"a"},
	}
	b, err := json.Marshal(page)
	require.NoError(t, err)
	assert.JSONEq(t, `{"items":["a"]}`, string(b))
}

func TestNewCursorPage_NormalizesNilSlice(t *testing.T) {
	// Handlers commonly hand us a nil `[]Article` when the upstream
	// query returned no rows. `null` would crash JS clients on `.map`;
	// the helper must emit `"items": []`.
	page := NewCursorPage[string](nil, nil)
	b, err := json.Marshal(page)
	require.NoError(t, err)
	assert.JSONEq(t, `{"items":[]}`, string(b))
}

func TestNewCursorPage_NilNextPageKey(t *testing.T) {
	page := NewCursorPage([]string{"a"}, nil)
	assert.Equal(t, "", page.NextPageKey)
}

func TestNewCursorPage_NonNilNextPageKey(t *testing.T) {
	key := "cursor-abc"
	page := NewCursorPage([]string{"a"}, &key)
	assert.Equal(t, "cursor-abc", page.NextPageKey)
}

func TestNewCursorPage_EmptyStringNextPageKey(t *testing.T) {
	// Some upstreams hand back `*string{""}` instead of `nil` to mean
	// "no more pages". The helper preserves that as-is — the field's
	// `omitempty` tag is what strips it on the wire.
	empty := ""
	page := NewCursorPage([]string{"a"}, &empty)
	assert.Equal(t, "", page.NextPageKey)
	b, err := json.Marshal(page)
	require.NoError(t, err)
	assert.JSONEq(t, `{"items":["a"]}`, string(b))
}
