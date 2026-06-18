package events

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPEmitter_HappyPath(t *testing.T) {
	var capturedBody []byte
	var capturedHeaders http.Header
	var capturedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedHeaders = r.Header.Clone()
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"event_id":"01HXY3F4Q5ABCDE0123456789Z","idempotent":false}`))
	}))
	defer srv.Close()

	emitter := NewHTTPEmitter(srv.URL, "test-key", "test-emitter", nil)
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	envelope := UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
		TS:        time.Date(2026, 5, 19, 7, 0, 50, 0, time.UTC),
		Props: map[string]any{
			"article_version_id": "abc",
			"read_seconds":       240,
			"completion_pct":     100,
		},
		Context: map[string]any{"app_version": "1.4.5"},
	}

	err := emitter.Emit(context.Background(), userID, envelope)
	require.NoError(t, err)

	// URL contract: internal route per ADR-011 §D2.2.
	assert.Equal(t, "/internal/api/v3/events", capturedPath)
	// X-User-ID header carries userID; body does NOT contain user_id.
	assert.Equal(t, userID.String(), capturedHeaders.Get("X-User-ID"))
	assert.Equal(t, "test-key", capturedHeaders.Get("X-Internal-API-Key"))
	assert.Equal(t, "test-emitter", capturedHeaders.Get("X-Kielo-Source-Service"))
	assert.Equal(t, "application/json", capturedHeaders.Get("Content-Type"))

	// Body shape matches ADR-011 §D2.2.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(capturedBody, &parsed))
	assert.Equal(t, "01HXY3F4Q5ABCDE0123456789Z", parsed["event_id"])
	assert.Equal(t, "article.read", parsed["event_type"])
	assert.NotContains(t, parsed, "user_id", "user_id MUST NOT be in the envelope body")
}

func TestHTTPEmitter_EmptyEventsURL_NoOp(t *testing.T) {
	// Phase-2 fallback: empty URL → Emit is a silent no-op so
	// emitter sites can wire HTTPEmitter into production before
	// kielo-events deploys in every env.
	emitter := NewHTTPEmitter("", "test-key", "test-emitter", nil)
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
	})
	assert.NoError(t, err)
}

func TestHTTPEmitter_MissingEventID_Error(t *testing.T) {
	emitter := NewHTTPEmitter("http://kielo-events", "k", "s", nil)
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "",
		EventType: "article.read",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EventID must be set")
}

func TestHTTPEmitter_MissingEventType_Error(t *testing.T) {
	emitter := NewHTTPEmitter("http://kielo-events", "k", "s", nil)
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EventType must be set")
}

func TestHTTPEmitter_SpineRejection_SurfacedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"VALIDATION_FAILED","message":"unknown event_type"}}`))
	}))
	defer srv.Close()

	emitter := NewHTTPEmitter(srv.URL, "k", "s", nil)
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "future.event",
		Props:     map[string]any{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422")
	assert.Contains(t, err.Error(), "VALIDATION_FAILED")
}

func TestHTTPEmitter_DefaultsTS(t *testing.T) {
	// Emitter MUST default TS to now() when caller leaves it zero.
	// Otherwise kielo-events would reject zero-time events as outside
	// the clock-skew window.
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	emitter := NewHTTPEmitter(srv.URL, "k", "s", nil)
	envelope := UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
		// TS deliberately zero
	}
	err := emitter.Emit(context.Background(), uuid.New(), envelope)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(capturedBody, &parsed))
	tsStr, ok := parsed["ts"].(string)
	require.True(t, ok)
	parsedTS, err := time.Parse(time.RFC3339Nano, tsStr)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), parsedTS, 5*time.Second,
		"ts defaults to roughly now() when caller leaves it zero")
}

func TestHTTPEmitter_DefaultsSchemaVersion(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	emitter := NewHTTPEmitter(srv.URL, "k", "s", nil)
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
		// SchemaVersion deliberately zero
	})
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(capturedBody, &parsed))
	// JSON numbers come back as float64.
	assert.Equal(t, float64(1), parsed["schema_version"])
}

func TestHTTPEmitter_NetworkFailure_Error(t *testing.T) {
	// Unreachable host — connection refused. Emit MUST return the
	// underlying error so the caller can log + retry.
	emitter := NewHTTPEmitter("http://127.0.0.1:1", "k", "s",
		&http.Client{Timeout: 100 * time.Millisecond})
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
	})
	require.Error(t, err)
}

func TestHTTPEmitter_NilReceiver_NoOp(t *testing.T) {
	// Defense in depth: a nil *HTTPEmitter (e.g. when a config wire
	// drops the emitter at startup) is a no-op rather than a panic.
	var emitter *HTTPEmitter
	err := emitter.Emit(context.Background(), uuid.New(), UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
	})
	assert.NoError(t, err)
}

func TestNoOpEmitter_AlwaysNil(t *testing.T) {
	// NoOpEmitter never errors regardless of envelope state. Used by
	// tests that compose with emitter-having services but don't want
	// to assert on emit behavior.
	var emitter NoOpEmitter
	err := emitter.Emit(context.Background(), uuid.UUID{}, UserActionEnvelope{})
	assert.NoError(t, err)
}

func TestHTTPEmitter_BodyMatchesExactSchema(t *testing.T) {
	// Pin the on-wire JSON keys exactly — drift here would invalidate
	// kielo-events' decoder.
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	emitter := NewHTTPEmitter(srv.URL, "k", "s", nil)
	envelope := UserActionEnvelope{
		EventID:       "01HXY3F4Q5ABCDE0123456789Z",
		EventType:     "video.watched",
		TS:            time.Date(2026, 5, 19, 7, 0, 50, 0, time.UTC),
		SchemaVersion: 1,
		Props: map[string]any{
			"video_id":       "v1",
			"watch_seconds":  120,
			"completion_pct": 100,
			"format":         "daily_word",
		},
		Context: map[string]any{
			"app_version": "1.4.5",
		},
	}
	require.NoError(t, emitter.Emit(context.Background(), uuid.New(), envelope))

	// Decode without UseNumber for stable map comparison.
	var got map[string]any
	require.NoError(t, json.Unmarshal(capturedBody, &got))

	// Required top-level keys per ADR-011 §D2.2.
	for _, key := range []string{"event_id", "event_type", "ts", "schema_version", "props"} {
		_, ok := got[key]
		assert.True(t, ok, "envelope missing required key %q", key)
	}
	// user_id MUST be in the header, not the body.
	assert.NotContains(t, got, "user_id")
}

// roundTripFunc lets a single function back http.RoundTripper for
// the network-failure test (not used right now but kept for parity
// with the consumer tests).
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestHTTPEmitter_RoundTripFuncCompiles(t *testing.T) {
	// Static use to keep the helper alive even with no current
	// consumers in this test file. Removes an unused-function lint.
	rt := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	_ = rt
}

// contractUserActionEnvelopePath returns the repo-relative path to
// the shared ADR-011 envelope fixture. Both this Go test and (when
// the Python emitter lands) the kielolearn-engine / kielo-events
// Python consumer tests load the SAME file — a divergence on either
// side trips its own test rather than silently 422-ing in production.
func contractUserActionEnvelopePath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "tests", "contract", "fixtures", name))
	require.NoError(t, err)
	require.FileExists(t, p, "ADR-011 contract fixture missing: %s", name)
	return p
}

func TestUserActionEnvelope_MatchesPrimaryFixture(t *testing.T) {
	// Pin the Go canonical marshaling of a primary (non-derived)
	// ADR-011 envelope against the shared fixture. Cross-language
	// drift on the wire format would be caught here on the Go side.
	envelope := UserActionEnvelope{
		EventID:       "01HXY3F4Q5ABCDE0123456789Z",
		EventType:     "article.read",
		TS:            time.Date(2026, 5, 19, 7, 0, 50, 0, time.UTC),
		SchemaVersion: 1,
		Props: map[string]any{
			"article_version_id": "22222222-2222-2222-2222-222222222222",
			"read_seconds":       240,
			"completion_pct":     100,
		},
		Context: map[string]any{
			"app_version":            "1.4.5",
			"learning_language_code": "fi",
			"support_language_code":  "vi",
		},
	}
	got, err := json.Marshal(envelope)
	require.NoError(t, err)

	want, err := os.ReadFile(contractUserActionEnvelopePath(t, "useraction_envelope.golden.json"))
	require.NoError(t, err)

	// JSONEq tolerates key ordering — Go sorts map keys
	// alphabetically while the fixture groups them semantically.
	assert.JSONEq(t, string(want), string(got),
		"UserActionEnvelope output diverged from the shared contract fixture; "+
			"if intentional, update tests/contract/fixtures/useraction_envelope.golden.json "+
			"AND any Python consumers that decode this shape (kielo-events test fixtures, "+
			"kielolearn-engine pydantic).")
}

func TestUserActionEnvelope_MatchesDerivedFixture(t *testing.T) {
	// Pin the derived-envelope shape (streak.advanced fired by the
	// user-service consumer as a side-effect of article.read). The
	// `derived_from` field MUST appear on the wire; omitempty drops
	// it for primary events but surfaces it here.
	envelope := UserActionEnvelope{
		EventID:       "01HXY3F4Q5DERIVED0000000Z0",
		EventType:     "streak.advanced",
		TS:            time.Date(2026, 5, 19, 7, 0, 51, 0, time.UTC),
		SchemaVersion: 1,
		Props: map[string]any{
			"from": 3,
			"to":   4,
		},
		DerivedFrom: "01HXY3F4Q5ABCDE0123456789Z",
	}
	got, err := json.Marshal(envelope)
	require.NoError(t, err)

	want, err := os.ReadFile(contractUserActionEnvelopePath(t, "useraction_envelope_derived.golden.json"))
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(got),
		"derived UserActionEnvelope output diverged from the shared contract fixture")
}

func TestUserActionEnvelope_OmitsDerivedFromForPrimary(t *testing.T) {
	// Defense in depth: a primary envelope (DerivedFrom == "") MUST
	// NOT serialize a `derived_from` key — the spine's V066
	// derived_from CHAR(26) FK rejects empty-string values, and the
	// downstream consumer's "skip derived events" filter relies on
	// the field being absent (or null) for primaries.
	envelope := UserActionEnvelope{
		EventID:   "01HXY3F4Q5ABCDE0123456789Z",
		EventType: "article.read",
		TS:        time.Date(2026, 5, 19, 7, 0, 50, 0, time.UTC),
		Props:     map[string]any{"article_version_id": "x", "read_seconds": 1, "completion_pct": 1},
	}
	got, err := json.Marshal(envelope)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(got, &parsed))
	_, present := parsed["derived_from"]
	assert.False(t, present, "primary envelope MUST NOT serialize derived_from (omitempty)")
}
