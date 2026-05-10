package llm_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/team-kielo-app/kielo-shared/seam/llm"
)

func TestGeminiJSONProvider_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Provider must POST to .../<model>:generateContent with key in query string.
		if !strings.HasSuffix(r.URL.Path, ":generateContent") {
			t.Errorf("expected :generateContent suffix, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "test-key" {
			t.Errorf("expected key=test-key, got %s", r.URL.Query().Get("key"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates":[{"content":{"parts":[{"text":"{\"hint\":\"hei\"}"}]}}]
		}`))
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL
	p.DefaultModel = "gemini-test"

	res, err := p.Generate(context.Background(), llm.Request{
		Prompt: "give me a hint",
		Task:   "convo_hint",
		ResponseSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hint": map[string]any{"type": "string"},
			},
		},
		Temperature: llm.Temp(0.7),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.RawText != `{"hint":"hei"}` {
		t.Errorf("expected hint JSON passthrough, got %q", res.RawText)
	}
	if res.Provider != "gemini:gemini-test" {
		t.Errorf("provider = %q", res.Provider)
	}
}

func TestGeminiJSONProvider_HTTP5xxClassifiedAsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassServerError {
		t.Errorf("ClassOf = %q, want http_5xx", got)
	}
}

func TestGeminiJSONProvider_HTTP4xxClassifiedAsClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx", got)
	}
}

func TestGeminiJSONProvider_TimeoutClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", &http.Client{Timeout: 10 * time.Millisecond})
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassTimeout {
		t.Errorf("ClassOf = %q, want timeout", got)
	}
}

func TestGeminiJSONProvider_EmptyCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassMissingPayload {
		t.Errorf("ClassOf = %q, want missing_payload", got)
	}
}

func TestGeminiJSONProvider_EmptyText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":""}]}}]}`))
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassEmptyResponse {
		t.Errorf("ClassOf = %q, want empty_response", got)
	}
}

func TestGeminiJSONProvider_DecodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := llm.NewGeminiJSONProvider("test-key", srv.Client())
	p.Endpoint = srv.URL

	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassDecode {
		t.Errorf("ClassOf = %q, want decode", got)
	}
}

func TestGeminiJSONProvider_MissingAPIKeyRejected(t *testing.T) {
	p := llm.NewGeminiJSONProvider("", nil)
	_, err := p.Generate(context.Background(), llm.Request{Prompt: "x", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx for missing key", got)
	}
}

func TestGeminiJSONProvider_EmptyPromptRejected(t *testing.T) {
	p := llm.NewGeminiJSONProvider("k", nil)
	_, err := p.Generate(context.Background(), llm.Request{Prompt: "", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassClientError {
		t.Errorf("ClassOf = %q, want http_4xx for empty prompt", got)
	}
}

func TestErrorImplementsErrorInterface(t *testing.T) {
	wrapped := errors.New("inner")
	e := &llm.Error{Class: llm.ErrorClassTimeout, Err: wrapped}
	if !errors.Is(e, wrapped) {
		t.Errorf("errors.Is failed for wrapped Error")
	}
}

// ─────────────────── MetricsDecorator wiring ──────────────────────────

type stubProvider struct {
	result *llm.Result
	err    error
	last   llm.Request
}

func (s *stubProvider) Generate(_ context.Context, req llm.Request) (*llm.Result, error) {
	s.last = req
	return s.result, s.err
}

func (s *stubProvider) ProviderID(_ llm.Request) string { return "stub-llm:v0" }

func TestMetricsDecorator_PassesRequestThroughOnSuccess(t *testing.T) {
	stub := &stubProvider{result: &llm.Result{RawText: "{}", Provider: "stub-llm:v0"}}
	dec := llm.WithMetrics(stub)

	res, err := dec.Generate(context.Background(), llm.Request{Prompt: "hi", Task: "convo_hint"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.RawText != "{}" {
		t.Errorf("payload passthrough broken")
	}
	if stub.last.Prompt != "hi" {
		t.Errorf("inner provider didn't receive request")
	}
}

func TestMetricsDecorator_PreservesProviderError(t *testing.T) {
	stub := &stubProvider{err: &llm.Error{Class: llm.ErrorClassServerError, Err: errors.New("503")}}
	dec := llm.WithMetrics(stub)

	_, err := dec.Generate(context.Background(), llm.Request{Prompt: "hi", Task: "convo_hint"})
	if got := llm.ClassOf(err); got != llm.ErrorClassServerError {
		t.Errorf("ClassOf = %q", got)
	}
}
