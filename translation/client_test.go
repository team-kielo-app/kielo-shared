package translation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the cross-service shared translation client. This is the
// pathway used by kielo-convo + kielo-communications-service.
//
// Sweep EEE (2026-05-30) — the client is now routing-aware
// (SelectTranslatorBatch picks opus-mt vs Gemini per pair × shape).
// Test inputs use sentence-length text for the OPUS_MT path so the
// HTTP mock at modelsURL is exercised only where a test re-enables a
// pair via withOpusMTPair; since 2026-08-30 the pair set is empty and
// every real pair dispatches through the Gemini path (engineURL).

// longSent is a sentence-length input that routes to the opus-mt
// backend on high-quality pairs (en→sv, en→fi, sv→en, fi→en) under
// Sweep EEE's ≤5-tokens-go-to-Gemini rule. Used by tests that mock
// only the models endpoint and need predictable opus-mt routing.
const longSent = "This is a long sentence with more than five tokens for opus-mt routing."

// withOpusMTPair re-enables (src, tgt) in opusMTHighQualityPairs for one
// test. The set has been EMPTY since the 2026-08-30 benchmark (Gemini won
// 41–4 on production text), so the opus-mt dispatch path is only reachable
// from tests that opt a pair back in. Not safe under t.Parallel.
func withOpusMTPair(t *testing.T, src, tgt string) {
	t.Helper()
	key := [2]string{src, tgt}
	_, had := opusMTHighQualityPairs[key]
	opusMTHighQualityPairs[key] = struct{}{}
	t.Cleanup(func() {
		if !had {
			delete(opusMTHighQualityPairs, key)
		}
	})
}

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
	withOpusMTPair(t, "en", "sv")
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
	// Long input on a (test-enabled) high-quality pair → opus-mt endpoint.
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

// 2026-08-30 — en↔fi / en↔sv left the high-quality set after a blinded
// production-text benchmark (Gemini 41–4, opus-mt meaning errors 30/60,
// 8-item batch 5–22 s vs ~1 s). Sentence-length input on those pairs must
// now reach the engine, and kielo-models must not be contacted at all.
func TestTranslateBatch_FormerOpusPairsRouteToGemini(t *testing.T) {
	var opusHit bool
	opus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		opusHit = true
		_, _ = w.Write([]byte(`{"translations": ["opus"]}`))
	}))
	defer opus.Close()
	var enginePaths []string
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enginePaths = append(enginePaths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations": ["gemini"]}`))
	}))
	defer engine.Close()

	c := NewClient(opus.URL, engine.URL, "k", nil)
	for _, pair := range [][2]string{{"en", "fi"}, {"fi", "en"}, {"en", "sv"}, {"sv", "en"}} {
		got := c.TranslateBatch(context.Background(), []string{longSent}, pair[0], pair[1])
		assert.Equal(t, []string{"gemini"}, got, "%s→%s", pair[0], pair[1])
	}
	assert.False(t, opusHit, "kielo-models must not be contacted for en↔fi / en↔sv")
	assert.Len(t, enginePaths, 4)
	for _, p := range enginePaths {
		assert.Equal(t, "/internal/translate-batch", p)
	}
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

// Regression: kielolearn-engine /internal/translate-batch now wraps its
// response in the v3 {"data": …} envelope. Pre-fix postBatch decoded the
// bare {"translations":[…]} shape, so the enveloped body produced
// body.Translations=nil → every Gemini-routed batch read as a full-batch
// failure → seam callProvider returned source (never cached) and convo
// re-translated the scenario description on EVERY detail open (10-30s).
// The fix routes the body through httputil.UnwrapDataEnvelope before
// decoding. This locks the enveloped shape in.
func TestTranslateBatch_DecodesEngineDataEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Enveloped, exactly as the engine emits post {data}-migration.
		_, _ = w.Write([]byte(`{"data":{"translations":["Xin chào"],"source_lang":"en","target_lang":"vi","provider":"llm"}}`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "k", nil)
	got := c.TranslateBatch(context.Background(), []string{"Hello"}, "en", "vi")

	assert.Equal(t, []string{"Xin chào"}, got,
		"enveloped engine response must decode to the inner translations")
}

// Sibling guard: the bare (un-enveloped) shape must keep decoding too, so
// the tolerant unwrap doesn't break kielo-models opus-mt (which stays
// bare) or any peer that hasn't migrated yet.
func TestTranslateBatch_StillDecodesBareResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"translations":["Xin chào"]}`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "k", nil)
	got := c.TranslateBatch(context.Background(), []string{"Hello"}, "en", "vi")

	assert.Equal(t, []string{"Xin chào"}, got,
		"bare response must still decode (opus-mt + unmigrated peers)")
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

	c := NewClient("", server.URL, "  ", nil)
	c.TranslateBatch(context.Background(), []string{longSent}, "en", "sv")
	assert.False(t, sawHeader, "blank API key must not be sent as a header")
}

func TestTranslateBatch_PadsWithEmptyWhenServerReturnsFewer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"translations": ["Hej hej"]}`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "", nil)
	got := c.TranslateBatch(context.Background(),
		[]string{longSent, longSent + " extra", longSent + " more"}, "en", "sv")
	assert.Equal(t, []string{"Hej hej", "", ""}, got)
}

func TestTranslateBatch_ReturnsNilOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient("", server.URL, "", nil)
	got := c.TranslateBatch(context.Background(), []string{longSent}, "en", "sv")
	assert.Nil(t, got)
}

func TestTranslateBatchWithContextsResult_ReportsHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient("", server.URL, "", nil)
	got, err := c.TranslateBatchWithContextsResult(
		context.Background(), []string{longSent}, nil, "en", "sv",
	)

	assert.Nil(t, got)
	require.EqualError(t, err, "translation upstream returned HTTP 502")
}

func TestTranslateBatchWithContextsResult_ReportsContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"translations":["late"]}`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	got, err := c.TranslateBatchWithContextsResult(ctx, []string{longSent}, nil, "en", "sv")

	assert.Nil(t, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestTranslateBatchWithContextsResult_ReportsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"translations":`))
	}))
	defer server.Close()

	c := NewClient("", server.URL, "", nil)
	got, err := c.TranslateBatchWithContextsResult(
		context.Background(), []string{longSent}, nil, "en", "sv",
	)

	assert.Nil(t, got)
	require.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected end of JSON input"))
	assert.Contains(t, err.Error(), "decode translation response")
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

	c := NewClient("", server.URL, "", nil)
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
