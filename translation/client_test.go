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

// Tests for the cross-service shared translation client. This is the
// pathway used by kielo-convo + kielo-communications-service.
//
// Sweep EEE (2026-05-30) — the client is now routing-aware
// (SelectTranslatorBatch picks opus-mt vs Gemini per pair × shape).
// Test inputs use sentence-length text for the OPUS_MT path so the
// HTTP mock at modelsURL is exercised; short-input tests dispatch
// through the Gemini path (engineURL).

// longSent is a sentence-length input that routes to the opus-mt
// backend on high-quality pairs (en→sv, en→fi, sv→en, fi→en) under
// Sweep EEE's ≤5-tokens-go-to-Gemini rule. Used by tests that mock
// only the models endpoint and need predictable opus-mt routing.
const longSent = "This is a long sentence with more than five tokens for opus-mt routing."

func TestNewClient_TrimsTrailingSlashOnURL(t *testing.T) {
	c := NewClient("https://models.example.com/", "", "", nil)
	assert.Equal(t, "https://models.example.com/api/v3/translations", c.URL())

	c2 := NewClient("https://models.example.com////", "", "", nil)
	assert.Equal(t, "https://models.example.com/api/v3/translations", c2.URL())
}

func TestNewClient_UsesDefaultHTTPClientWhenNil(t *testing.T) {
	c := NewClient("https://models.example.com", "", "", nil)
	assert.NotNil(t, c.httpClient, "nil http client must be replaced with a default")
}

func TestIsAvailable(t *testing.T) {
	var nilClient *Client
	assert.False(t, nilClient.IsAvailable())

	// Both URLs blank → false (can't translate via either backend).
	assert.False(t, NewClient("", "", "", nil).IsAvailable())
	assert.False(t, NewClient("   ", "  ", "", nil).IsAvailable())

	// Either backend configured → true. Sweep EEE: per-call routing
	// picks which one runs, so having ONE backend is enough to
	// declare the client available.
	assert.True(t, NewClient("https://models.example.com", "", "", nil).IsAvailable())
	assert.True(t, NewClient("", "https://engine.example.com", "", nil).IsAvailable())
	assert.True(t, NewClient("https://models.example.com", "https://engine.example.com", "", nil).IsAvailable())
}

func TestTranslate_EmptyInputReturnsEmpty(t *testing.T) {
	c := NewClient("https://unused.example.com", "", "", nil)
	assert.Equal(t, "", c.Translate(context.Background(), "", "en", "sv"))
	assert.Equal(t, "", c.Translate(context.Background(), "   ", "en", "sv"))
}

func TestTranslateBatch_RoutesLongInputToOpusMT(t *testing.T) {
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
		_, _ = w.Write([]byte(`{"translations": ["Hej hej"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", "test-api-key", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{longSent}, "en", "sv")

	assert.Equal(t, []string{"Hej hej"}, got)
	// Sweep EEE: long input on high-quality pair (en→sv) → opus-mt.
	assert.Equal(t, "/api/v3/translations", receivedPath)
	assert.Equal(t, []string{longSent}, receivedBody.Texts)
	assert.Equal(t, "en", receivedBody.SourceLang)
	assert.Equal(t, "sv", receivedBody.TargetLang)
	assert.Equal(t, "test-api-key", receivedAPIKey)
	assert.Equal(t, "application/json", receivedContentType)
}

// Sweep EEE — short input on a high-quality pair now routes to the
// Gemini endpoint (`/internal/translate-batch`). Pre-EEE this would
// have hit the opus-mt endpoint and produced smyger→smugg-class
// junk for single-token inputs.
func TestTranslateBatch_RoutesShortInputToGemini(t *testing.T) {
	var receivedPath string
	var receivedBody batchRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &receivedBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["Spara"]}`))
	}))
	defer server.Close()

	// Configure engine URL, not models URL — the short-input path
	// should hit the engine.
	c := NewClient("", server.URL, "k", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{"Save"}, "en", "sv")

	assert.Equal(t, []string{"Spara"}, got)
	assert.Equal(t, "/internal/translate-batch", receivedPath)
	assert.Equal(t, []string{"Save"}, receivedBody.Texts)
	assert.Equal(t, "en", receivedBody.SourceLang)
	assert.Equal(t, "sv", receivedBody.TargetLang)
}

// Sweep EEE — non-high-quality pair (en→vi) always routes to
// Gemini regardless of input length. Pre-EEE this would have hit
// kielo-models en-vi which empirically produced junk on title-class
// inputs ("New Track" → "Mới").
func TestTranslateBatch_RoutesNonOpusMTPairToGemini(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["Xin chào thế giới với nội dung dài hơn năm token"]}`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "k", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{"Hello world with longer content than five tokens"}, "en", "vi")

	assert.NotEmpty(t, got)
	assert.Equal(t, "/internal/translate-batch", receivedPath)
}

// Sweep EEE — src == tgt routes to passthrough; no HTTP call.
func TestTranslateBatch_PassthroughOnSameLocale(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	c := NewClient(server.URL, server.URL, "", nil)
	got := c.TranslateBatch(context.Background(), []string{longSent}, "en", "en")

	assert.Equal(t, []string{longSent}, got, "passthrough returns input unchanged")
	assert.False(t, called, "src == tgt must not make any HTTP call")
}

func TestTranslateBatch_SkipsAPIKeyHeaderWhenBlank(t *testing.T) {
	var sawHeader bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawHeader = r.Header["X-Internal-Api-Key"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["x"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", "  ", nil)
	c.TranslateBatch(context.Background(), []string{longSent}, "en", "sv")
	assert.False(t, sawHeader, "blank API key must not be sent as a header")
}

func TestTranslateBatch_PadsWithEmptyWhenServerReturnsFewer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"translations": ["Hej hej"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", "", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{longSent, longSent + " extra", longSent + " more"}, "en", "sv")
	assert.Equal(t, []string{"Hej hej", "", ""}, got)
}

func TestTranslateBatch_ReturnsNilOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient(server.URL, "", "", nil)
	got := c.TranslateBatch(context.Background(), []string{longSent}, "en", "sv")
	assert.Nil(t, got)
}

func TestTranslateBatch_ReturnsNilWhenUnavailable(t *testing.T) {
	c := NewClient("", "", "", nil)
	got := c.TranslateBatch(context.Background(), []string{longSent}, "en", "sv")
	assert.Nil(t, got)
}

func TestTranslateBatch_EmptyInputsSkipsNetwork(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	c := NewClient(server.URL, server.URL, "", nil)
	got := c.TranslateBatch(context.Background(), []string{}, "en", "sv")
	assert.Nil(t, got)
	assert.False(t, called, "no network call must be made for empty input slice")
}

func TestTranslateBatch_HonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"translations": ["x"]}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, "", "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := c.TranslateBatch(ctx, []string{longSent}, "en", "sv")
	assert.Nil(t, got)
}

func TestURL_ReturnsCanonicalEndpoint(t *testing.T) {
	c := NewClient("https://models.example.com", "", "", nil)
	assert.Equal(t, "https://models.example.com/api/v3/translations", c.URL())

	empty := NewClient("", "", "", nil)
	assert.True(t, strings.HasSuffix(empty.URL(), "/api/v3/translations"))
}
