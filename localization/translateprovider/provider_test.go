package translateprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/team-kielo-app/kielo-shared/localization"
	sharedtranslation "github.com/team-kielo-app/kielo-shared/translation"
)

// newStubServer stands up a fake kielo-models / engine translation
// endpoint that echoes texts with a marker so tests can assert which
// inputs reached the upstream. Keeps the adapter testable without
// spinning up a real translation backend.
//
// Sweep EEE (2026-05-30) — the stub handles BOTH wire URLs (opus-mt
// `/api/v3/translations` and engine `/internal/translate-batch`)
// because the routing decision in kielo-shared/translation can pick
// either depending on (pair, n_tokens). Tests configure the same
// `server.URL` as both modelsURL and engineURL so the stub catches
// dispatches regardless of routing.
func newStubServer(t *testing.T) *httptest.Server {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Texts      []string `json:"texts"`
			SourceLang string   `json:"source_lang"`
			TargetLang string   `json:"target_lang"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := make([]string, len(req.Texts))
		for i, text := range req.Texts {
			out[i] = "[" + req.TargetLang + "] " + text
		}
		_ = json.NewEncoder(w).Encode(struct {
			Translations []string `json:"translations"`
		}{out})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/translations", handler)
	mux.HandleFunc("/internal/translate-batch", handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestProvider_TranslateBatch_HappyPath(t *testing.T) {
	server := newStubServer(t)
	// Sweep EEE (2026-05-30): NewClient added engineURL parameter so
	// the routing decision can dispatch short input + non-opus pairs
	// to Gemini. Pass empty engineURL here so the test stays on the
	// opus-mt path that the existing httptest server mocks.
	//
	// Sweep EEE note: items[1] = "Hello" is single-token and would
	// route to Gemini under EEE, NOT opus-mt. To keep the test
	// exercising the opus-mt path (which is what this test pins),
	// the input text below is long enough to stay on opus-mt for
	// en→vi… wait, en→vi is NOT in the high-quality pair set so it
	// always routes to Gemini. This test stub mocks the opus-mt URL
	// but EEE routes en→vi to engine — the test as written would
	// need the engine URL configured to pass post-EEE.
	//
	// Resolution: pass server.URL as BOTH modelsURL and engineURL so
	// the EEE routing reaches our stub regardless of which path the
	// decision picks. The stub server handles `/api/v3/translations`
	// AND can also be augmented to handle `/internal/translate-batch`.
	client := sharedtranslation.NewClient(server.URL, server.URL, "test-api-key", nil)
	provider := New(client, "kielo-models:test")

	items := []localization.TranslationItem{
		{Text: "Order a coffee"},
		{Text: "Hello"},
	}
	results, err := provider.TranslateBatch(context.Background(), items,
		localization.TranslateOptions{SourceLocale: "en", TargetLocale: "vi"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d, want 2", len(results))
	}
	if results[0].Text != "[vi] Order a coffee" {
		t.Fatalf("result[0].Text=%q", results[0].Text)
	}
	if results[0].Provider != "kielo-models:test" {
		t.Fatalf("result[0].Provider=%q", results[0].Provider)
	}
}

func TestProvider_TranslateBatch_EmptyInputReturnsNil(t *testing.T) {
	provider := New(nil, "x")
	results, err := provider.TranslateBatch(context.Background(), nil,
		localization.TranslateOptions{SourceLocale: "en", TargetLocale: "vi"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results for nil items, got %v", results)
	}
}

func TestProvider_TranslateBatch_NilClientIsSafe(t *testing.T) {
	provider := New(nil, "x")
	results, err := provider.TranslateBatch(context.Background(),
		[]localization.TranslationItem{{Text: "Hello"}},
		localization.TranslateOptions{SourceLocale: "en", TargetLocale: "vi"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if results != nil {
		t.Fatalf("nil client must return nil results, got %v", results)
	}
}

func TestProvider_ProviderID_Default(t *testing.T) {
	if p := New(nil, ""); p.ProviderID() != "kielo-models:v1" {
		t.Fatalf("default provider id mismatch: %q", p.ProviderID())
	}
	if p := New(nil, "custom:v2"); p.ProviderID() != "custom:v2" {
		t.Fatalf("explicit provider id mismatch: %q", p.ProviderID())
	}
}

// Compile-time check: Provider implements localization.Provider.
var _ localization.Provider = (*Provider)(nil)
