package media

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for media URL construction. Every service that returns a
// media asset to a client goes through PreferredVariantURL →
// gcs.JoinServeBaseAndObjectPath to produce the actual URL. The
// join logic (two branches: CDN/direct vs GCS API) is unit-tested
// directly in kielo-shared/gcs/serve_url_test.go — this file
// covers the media-layer composition on top of it (variant
// selection, JSONB parsing).

func TestVariantsFromJSON_EmptyInputReturnsNil(t *testing.T) {
	// An empty or nil JSONB payload → nil map, no error. Callers
	// treat nil and "row missing" as equivalent — the alternative
	// (erroring on empty) would force every caller to distinguish
	// these cases.
	got, err := VariantsFromJSON(nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = VariantsFromJSON([]byte{})
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestVariantsFromJSON_ParsesKeyedMap(t *testing.T) {
	raw := []byte(`{
		"main":    {"path": "img.jpg", "mime_type": "image/jpeg", "width": 1200},
		"preview": {"path": "thumb.jpg", "width": 240}
	}`)
	got, err := VariantsFromJSON(raw)
	require.NoError(t, err)
	assert.Equal(t, "img.jpg", got["main"].Path)
	assert.Equal(t, "image/jpeg", got["main"].MimeType)
	assert.Equal(t, 1200, got["main"].Width)
	assert.Equal(t, "thumb.jpg", got["preview"].Path)
}

func TestVariantsFromJSON_IgnoresUnknownFields(t *testing.T) {
	// The production JSONB often carries extra fields the processor
	// emits but callers don't care about (e.g. "processing_metadata").
	// Unmarshal must not fail on those.
	raw := []byte(`{"main": {"path": "x.jpg", "future_field": 42}}`)
	got, err := VariantsFromJSON(raw)
	require.NoError(t, err)
	assert.Equal(t, "x.jpg", got["main"].Path)
}

func TestVariantsFromJSON_MalformedJSONBubblesError(t *testing.T) {
	raw := []byte(`{not valid json`)
	_, err := VariantsFromJSON(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal variants")
}

func TestPreferredVariantURL_UsesFirstMatchingKey(t *testing.T) {
	// keyPriority enforces ordering: "main" before "preview". If the
	// first key exists with a non-empty path, it wins — the function
	// does NOT fall through to lower-priority keys unless the
	// higher-priority one is missing or empty.
	base := "https://cdn.example.com/assets/"
	variants := map[string]Variant{
		"main":    {Path: "full.jpg"},
		"preview": {Path: "thumb.jpg"},
	}
	got := PreferredVariantURL(base, variants, "main", "preview")
	assert.Equal(t, "https://cdn.example.com/assets/full.jpg", got)

	// Priority inverted → preview wins.
	got = PreferredVariantURL(base, variants, "preview", "main")
	assert.Equal(t, "https://cdn.example.com/assets/thumb.jpg", got)
}

func TestPreferredVariantURL_SkipsEmptyPathVariants(t *testing.T) {
	// A variant key that exists in the map but has an empty Path
	// (the processor sometimes emits placeholder entries during
	// staged processing) must be skipped so we fall through to the
	// next key, not return a broken URL.
	base := "https://cdn.example.com/assets/"
	variants := map[string]Variant{
		"main":    {Path: "  "}, // whitespace-only path → empty after trim
		"preview": {Path: "ok.jpg"},
	}
	got := PreferredVariantURL(base, variants, "main", "preview")
	assert.Equal(t, "https://cdn.example.com/assets/ok.jpg", got)
}

func TestPreferredVariantURL_ReturnsEmptyWhenNoMatch(t *testing.T) {
	// No matching key → "", not a broken URL with "undefined" or similar.
	base := "https://cdn.example.com/assets/"
	variants := map[string]Variant{
		"other": {Path: "x.jpg"},
	}
	got := PreferredVariantURL(base, variants, "main", "preview")
	assert.Equal(t, "", got)
}

func TestPreferredVariantURL_GuardsEmptyBaseAndVariants(t *testing.T) {
	// An empty base (e.g. storage not configured) or empty variants
	// map (e.g. row exists but no variants processed yet) → "".
	assert.Equal(t, "", PreferredVariantURL("", map[string]Variant{"a": {Path: "x.jpg"}}, "a"))
	assert.Equal(t, "", PreferredVariantURL("https://cdn/", nil, "a"))
	assert.Equal(t, "", PreferredVariantURL("https://cdn/", map[string]Variant{}, "a"))
}

func TestServeBaseURL_DelegatesToGCSHelper(t *testing.T) {
	// Integration sanity: the wrapper must produce the same canonical
	// shape that gcs.BuildServeBaseURL produces. Specifically the
	// trailing slash on the prefix must be present so downstream
	// joins produce "base+variant" cleanly.
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	got := ServeBaseURL("bucket", "media")
	assert.True(t, strings.HasSuffix(got, "/media/"),
		"serve base URL must end with '/<prefix>/' for downstream joins")
}
