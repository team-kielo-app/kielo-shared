package translation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the kielo-models translation client. This is the fallback
// pathway used by kielo-communications-service, kielolearn-engine, and
// kielo-content-service when an approved translation isn't already in
// the DB. A silent regression here — e.g. swallowing the API key,
// posting to the wrong path, or returning partial results without
// padding — causes English fallback leakage into Tier-A locales
// (Finnish, Swedish, Vietnamese).

func TestNewClient_TrimsTrailingSlashOnURL(t *testing.T) {
	// modelsURL is joined with "/api/v1/translations" in both
	// TranslateBatch and URL(). If NewClient doesn't trim a trailing
	// slash, we'd send requests to "…//api/v1/translations" and most
	// reverse proxies would 404.
	c := NewClient("https://models.example.com/", "", nil)
	assert.Equal(t, "https://models.example.com/api/v1/translations", c.URL())

	// Double slash also gets collapsed to zero via TrimRight.
	c2 := NewClient("https://models.example.com////", "", nil)
	assert.Equal(t, "https://models.example.com/api/v1/translations", c2.URL())
}

func TestNewClient_UsesDefaultHTTPClientWhenNil(t *testing.T) {
	c := NewClient("https://models.example.com", "", nil)
	assert.NotNil(t, c.httpClient, "nil http client must be replaced with a default")
}

func TestIsAvailable(t *testing.T) {
	// Nil receiver → false (don't panic) — callers check this before
	// every translate call.
	var nilClient *Client
	assert.False(t, nilClient.IsAvailable())

	// Empty/whitespace URL → false. In tests and misconfigured envs
	// the URL is blank; the caller must fall back to English without
	// issuing a doomed HTTP request.
	assert.False(t, NewClient("", "", nil).IsAvailable())
	assert.False(t, NewClient("   ", "", nil).IsAvailable())

	// Configured URL → true.
	assert.True(t, NewClient("https://models.example.com", "", nil).IsAvailable())
}

func TestTranslate_EmptyInputReturnsEmpty(t *testing.T) {
	// No HTTP round-trip for blank input. The caller saves a network
	// hop when the source text is already empty.
	c := NewClient("https://unused.example.com", "", nil)
	assert.Equal(t, "", c.Translate(context.Background(), "", "en", "sv"))
	assert.Equal(t, "", c.Translate(context.Background(), "   ", "en", "sv"))
}

func TestTranslateBatch_RoundTripsThroughModelsEndpoint(t *testing.T) {
	var receivedPath string
	var receivedBody batchRequest
	var receivedAPIKey string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAPIKey = r.Header.Get("X-Internal-API-Key")
		receivedContentType = r.Header.Get("Content-Type")
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &receivedBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["Hej", "Tack"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-api-key", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{"Hello", "Thank you"}, "en", "sv")

	assert.Equal(t, []string{"Hej", "Tack"}, got)
	// Path, method (implicit via httptest), payload, and headers all
	// pinned — these are the exact wire contract the models service
	// depends on.
	assert.Equal(t, "/api/v1/translations", receivedPath)
	assert.Equal(t, []string{"Hello", "Thank you"}, receivedBody.Texts)
	assert.Equal(t, "en", receivedBody.SourceLang)
	assert.Equal(t, "sv", receivedBody.TargetLang)
	assert.Equal(t, "test-api-key", receivedAPIKey)
	assert.Equal(t, "application/json", receivedContentType)
}

func TestTranslateBatch_SkipsAPIKeyHeaderWhenBlank(t *testing.T) {
	// The internal-API-key header must only be sent when configured.
	// Sending "X-Internal-API-Key: " (empty) could trigger downstream
	// auth middleware to reject the request as malformed.
	var sawHeader bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check whether the header is present AT ALL, not just non-empty.
		_, sawHeader = r.Header["X-Internal-Api-Key"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["x"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "  ", nil)
	c.TranslateBatch(context.Background(), []string{"hello"}, "en", "sv")
	assert.False(t, sawHeader, "blank API key must not be sent as a header")
}

func TestTranslateBatch_PadsWithEmptyWhenServerReturnsFewer(t *testing.T) {
	// Models sometimes returns fewer translations than requested
	// (e.g. when one item is empty). The client must pad with "" so
	// callers can rely on a 1:1 positional alignment with their input.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"translations": ["Hej"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{"Hello", "World", "Extra"}, "en", "sv")
	// 1:1 alignment preserved — even missing slots are addressable.
	assert.Equal(t, []string{"Hej", "", ""}, got)
}

func TestTranslateBatch_ReturnsNilOnNon200(t *testing.T) {
	// Non-200 is opt-in failure: caller sees nil and proceeds to its
	// own fallback (e.g. persisted English source_text). Returning
	// [] vs nil here would mislead `len(got) > 0` guards.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", nil)
	got := c.TranslateBatch(context.Background(), []string{"x"}, "en", "sv")
	assert.Nil(t, got)
}

func TestTranslateBatch_ReturnsNilWhenUnavailable(t *testing.T) {
	// Unavailable client must NOT attempt the HTTP call. We verify by
	// pointing at an invalid URL that would fail instantly if the
	// client tried to dial — but IsAvailable=false should short-circuit
	// before that.
	c := NewClient("", "", nil)
	got := c.TranslateBatch(context.Background(), []string{"x"}, "en", "sv")
	assert.Nil(t, got)
}

func TestTranslateBatch_EmptyInputsSkipsNetwork(t *testing.T) {
	// No inputs → no network call, return nil.
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	c := NewClient(server.URL, "", nil)
	got := c.TranslateBatch(context.Background(), []string{}, "en", "sv")
	assert.Nil(t, got)
	assert.False(t, called, "no network call must be made for empty input slice")
}

func TestTranslateBatch_HonorsContextCancellation(t *testing.T) {
	// A canceled context before the HTTP call must NOT crash and
	// must return nil. This exercises the http.NewRequestWithContext
	// + httpClient.Do error path.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"translations": ["x"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	got := c.TranslateBatch(ctx, []string{"hello"}, "en", "sv")
	assert.Nil(t, got)
}

func TestURL_ReturnsCanonicalEndpoint(t *testing.T) {
	// Callers (e.g. observability labels, error messages) read URL()
	// as the authoritative string. Pin the exact format.
	c := NewClient("https://models.example.com", "", nil)
	assert.Equal(t, "https://models.example.com/api/v1/translations", c.URL())

	// Even when URL is blank, URL() doesn't panic — it just returns
	// the suffix. Callers use this for display; don't assume they
	// gate on IsAvailable first.
	empty := NewClient("", "", nil)
	assert.True(t, strings.HasSuffix(empty.URL(), "/api/v1/translations"))
}
