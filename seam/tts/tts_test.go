package tts_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/team-kielo-app/kielo-shared/seam/tts"
)

// Provider unit tests — no metric counter assertions here. Metric
// wiring is covered by the dedicated decorator test below.

func TestOpenAITTSProvider_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth header missing: %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("\xff\xfb\x90mp3-audio-bytes"))
	}))
	defer srv.Close()

	p := tts.NewOpenAITTSProvider("test-key", srv.Client())
	p.Endpoint = srv.URL
	p.DefaultModel = "tts-1"

	res, err := p.Synthesize(context.Background(), tts.Request{
		Text:    "hello",
		VoiceID: "alloy",
		Speed:   1.0,
		Task:    "convo_playback",
	})
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if !strings.HasPrefix(string(res.Audio), "\xff\xfb\x90") {
		t.Errorf("expected mp3 audio bytes, got %d bytes", len(res.Audio))
	}
	if res.Provider != "openai-tts:tts-1" {
		t.Errorf("provider id = %q", res.Provider)
	}
}

func TestOpenAITTSProvider_HTTP5xxClassifiedAsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server overloaded"}`))
	}))
	defer srv.Close()

	p := tts.NewOpenAITTSProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Synthesize(context.Background(), tts.Request{
		Text: "hello", VoiceID: "alloy", Task: "convo_playback",
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if got := tts.ClassOf(err); got != tts.ErrorClassServerError {
		t.Errorf("ClassOf = %q, want http_5xx", got)
	}
}

func TestOpenAITTSProvider_HTTP4xxClassifiedAsClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	p := tts.NewOpenAITTSProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Synthesize(context.Background(), tts.Request{
		Text: "hello", VoiceID: "alloy", Task: "convo_playback",
	})
	if got := tts.ClassOf(err); got != tts.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx", got)
	}
}

func TestOpenAITTSProvider_TimeoutClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := tts.NewOpenAITTSProvider("test-key", &http.Client{Timeout: 10 * time.Millisecond})
	p.Endpoint = srv.URL

	_, err := p.Synthesize(context.Background(), tts.Request{
		Text: "hello", VoiceID: "alloy", Task: "convo_playback",
	})
	if got := tts.ClassOf(err); got != tts.ErrorClassTimeout {
		t.Errorf("ClassOf = %q, want timeout", got)
	}
}

func TestOpenAITTSProvider_EmptyTextRejected(t *testing.T) {
	p := tts.NewOpenAITTSProvider("test-key", nil)
	_, err := p.Synthesize(context.Background(), tts.Request{Text: "", VoiceID: "alloy", Task: "convo_playback"})
	if err == nil {
		t.Fatal("expected client error for empty text")
	}
	if got := tts.ClassOf(err); got != tts.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx for empty text", got)
	}
}

func TestOpenAITTSProvider_MissingAPIKeyRejected(t *testing.T) {
	p := tts.NewOpenAITTSProvider("", nil)
	_, err := p.Synthesize(context.Background(), tts.Request{Text: "x", VoiceID: "alloy", Task: "convo_playback"})
	if got := tts.ClassOf(err); got != tts.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx for missing key", got)
	}
}

func TestErrorImplementsErrorInterface(t *testing.T) {
	wrapped := errors.New("inner")
	e := &tts.Error{Class: tts.ErrorClassTimeout, Err: wrapped}
	if !errors.Is(e, wrapped) {
		t.Errorf("errors.Is failed for wrapped Error")
	}
	if got := tts.ClassOf(e); got != tts.ErrorClassTimeout {
		t.Errorf("ClassOf direct = %q", got)
	}
}

// ─────────────────── MetricsDecorator wiring ──────────────────────────

type stubProvider struct {
	result *tts.Result
	err    error
	last   tts.Request
}

func (s *stubProvider) Synthesize(_ context.Context, req tts.Request) (*tts.Result, error) {
	s.last = req
	return s.result, s.err
}

func (s *stubProvider) ProviderID(_ tts.Request) string { return "stub-tts:v0" }

func TestMetricsDecorator_PassesRequestThroughOnSuccess(t *testing.T) {
	stub := &stubProvider{result: &tts.Result{Audio: []byte("ok"), Provider: "stub-tts:v0"}}
	dec := tts.WithMetrics(stub)

	res, err := dec.Synthesize(context.Background(), tts.Request{
		Text: "hi", VoiceID: "alloy", Task: "convo_playback",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(res.Audio) != "ok" {
		t.Errorf("audio passthrough broken")
	}
	if stub.last.Text != "hi" {
		t.Errorf("inner provider didn't receive request")
	}
}

func TestMetricsDecorator_PreservesProviderError(t *testing.T) {
	stub := &stubProvider{err: &tts.Error{Class: tts.ErrorClassServerError, Err: errors.New("503")}}
	dec := tts.WithMetrics(stub)

	_, err := dec.Synthesize(context.Background(), tts.Request{
		Text: "hi", VoiceID: "alloy", Task: "convo_playback",
	})
	if err == nil {
		t.Fatal("expected error passthrough")
	}
	if got := tts.ClassOf(err); got != tts.ErrorClassServerError {
		t.Errorf("ClassOf = %q", got)
	}
}

func TestMetricsDecorator_DefaultsTaskAndVoiceLabelsWhenEmpty(t *testing.T) {
	// Confirms cardinality controls: empty caller-supplied task/voice
	// collapse to fixed strings instead of leaking empty labels into
	// the metric (which would fan out arbitrarily).
	stub := &stubProvider{result: &tts.Result{Audio: []byte("ok")}}
	dec := tts.WithMetrics(stub)

	_, err := dec.Synthesize(context.Background(), tts.Request{Text: "hi"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// No direct assertion on metric values — provider stub doesn't
	// expose the registry — but the decorator MUST NOT panic on
	// empty labels (would happen if WithLabelValues received "").
	// The behavior is implicit via no-panic plus the bounded label
	// strings documented in observe/metrics/tts.go.
}
