package translation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/team-kielo-app/kielo-shared/observe/httputil"
)

// Client is the cross-service shared translation client used by
// kielo-convo + kielo-communications-service.
//
// Sweep EEE (2026-05-30) — routing-aware. TranslateBatch consults
// SelectTranslatorBatch (in routing.go, this same package) and
// dispatches to either kielo-models /api/v3/translations (opus-mt)
// or kielolearn-engine /internal/translate-batch (Gemini). The
// pre-EEE direct-opus-mt-only behavior is preserved when engineURL
// is empty (degraded fallback).
type Client struct {
	modelsURL  string
	engineURL  string
	apiKey     string
	httpClient *http.Client
}

type batchRequest struct {
	Texts      []string `json:"texts"`
	SourceLang string   `json:"source_lang"`
	TargetLang string   `json:"target_lang"`
	// Optional per-text disambiguation hints, parallel to Texts. Omitted
	// entirely when empty (omitempty) so an un-hinted batch serializes exactly
	// as before — which matters because the engine keys its LLM cache off the
	// texts, and a changed payload shape would otherwise orphan every existing
	// entry. Only the Gemini/LLM backend can act on these; opus-mt is an NMT
	// model that cannot take instructions and ignores the field.
	Contexts []string `json:"contexts,omitempty"`
}

type batchResponse struct {
	Translations []string `json:"translations"`
}

// NewClient constructs the routing-aware translation client.
//
// Sweep EEE — engineURL was added so the client can route short
// input + non-high-quality pairs to the Gemini-backed endpoint.
// Existing callers passing only modelsURL get degraded behavior:
// short inputs fall through to opus-mt and produce smyger→smugg-
// class junk. Migrate by passing kielolearn-engine's base URL.
func NewClient(modelsURL, engineURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = httputil.NewClient(30 * time.Second)
	}
	return &Client{
		modelsURL:  strings.TrimRight(modelsURL, "/"),
		engineURL:  strings.TrimRight(engineURL, "/"),
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

func (c *Client) IsAvailable() bool {
	if c == nil {
		return false
	}
	// Either backend being configured is enough — the per-call routing
	// decision picks one. Pre-EEE this checked only modelsURL.
	return strings.TrimSpace(c.modelsURL) != "" ||
		strings.TrimSpace(c.engineURL) != ""
}

func (c *Client) Translate(ctx context.Context, text, sourceLang, targetLang string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	translations := c.TranslateBatch(ctx, []string{text}, sourceLang, targetLang)
	if len(translations) == 0 {
		return ""
	}
	return translations[0]
}

// TranslateBatch is the routing-aware batch translator.
//
// Sweep EEE — consults SelectTranslatorBatch(src, tgt, texts) and
// dispatches:
//
//	BackendOpusMT     → POST modelsURL/api/v3/translations
//	BackendGemini     → POST engineURL/internal/translate-batch
//	BackendPassthrough → return texts unchanged
//
// On per-backend failure the function returns nil (preserving the
// pre-EEE failure contract). Callers handle empty/nil results by
// falling back to the source text — the existing pattern in
// kielo-convo + kielo-communications.
func (c *Client) TranslateBatch(ctx context.Context, texts []string, sourceLang, targetLang string) []string {
	return c.TranslateBatchWithContexts(ctx, texts, nil, sourceLang, targetLang)
}

// TranslateBatchWithContexts is TranslateBatch plus per-text disambiguation
// hints parallel to `texts` (nil, or a shorter slice, means no hint).
//
// Additive rather than a signature change on TranslateBatch: that method has
// ~47 call sites across four submodules, none of which have a hint to pass.
// Only the localization seam knows the UI key behind a string, so only its
// provider adapter calls this. Hints reach the LLM backend only —
// see batchRequest.Contexts.
func (c *Client) TranslateBatchWithContexts(ctx context.Context, texts, contexts []string, sourceLang, targetLang string) []string {
	translated, _ := c.TranslateBatchWithContextsResult(ctx, texts, contexts, sourceLang, targetLang)
	return translated
}

// TranslateBatchWithContextsResult is the diagnostic form used by the
// localization provider adapter. Legacy callers intentionally keep the
// nil-on-failure contract of TranslateBatchWithContexts; the seam needs the
// cause so its fallback log can distinguish a timeout, an HTTP failure, and an
// invalid response instead of collapsing all three into a result-count mismatch.
func (c *Client) TranslateBatchWithContextsResult(
	ctx context.Context,
	texts, contexts []string,
	sourceLang, targetLang string,
) ([]string, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	if !c.IsAvailable() {
		return nil, errors.New("translation client unavailable")
	}

	backend := SelectTranslatorBatch(sourceLang, targetLang, texts)
	switch backend {
	case BackendPassthrough:
		return slices.Clone(texts), nil
	case BackendOpusMT:
		// opus-mt cannot use hints — drop them rather than send a field the
		// NMT service would have to ignore.
		return c.dispatchOpusMTResult(ctx, texts, sourceLang, targetLang)
	case BackendGemini:
		return c.dispatchGeminiResult(ctx, texts, contexts, sourceLang, targetLang)
	default:
		return nil, fmt.Errorf("unsupported translation backend %q", backend)
	}
}

// dispatchOpusMTResult POSTs to kielo-models /api/v3/translations and retains
// the failure cause for callers that can report it.
func (c *Client) dispatchOpusMTResult(ctx context.Context, texts []string, sourceLang, targetLang string) ([]string, error) {
	if strings.TrimSpace(c.modelsURL) == "" {
		return nil, errors.New("opus-mt backend is not configured")
	}
	return c.postBatchResult(ctx, c.modelsURL+"/api/v3/translations", texts, sourceLang, targetLang)
}

// dispatchGeminiResult POSTs to kielolearn-engine /internal/translate-batch.
// Same payload + response shape as opus-mt so the wire format is
// uniform across backends.
func (c *Client) dispatchGeminiResult(
	ctx context.Context,
	texts, contexts []string,
	sourceLang, targetLang string,
) ([]string, error) {
	if strings.TrimSpace(c.engineURL) == "" {
		return nil, errors.New("gemini backend is not configured")
	}
	return c.postBatchWithContextsResult(
		ctx, c.engineURL+"/internal/translate-batch", texts, contexts, sourceLang, targetLang,
	)
}

// postBatchResult sends the wire-uniform translation batch request and
// decodes the standard {"translations": [...]} response. Internal
// helper shared by the two backend dispatch functions so the HTTP
// plumbing isn't duplicated.
func (c *Client) postBatchResult(
	ctx context.Context,
	url string,
	texts []string,
	sourceLang, targetLang string,
) ([]string, error) {
	return c.postBatchWithContextsResult(ctx, url, texts, nil, sourceLang, targetLang)
}

// postBatchWithContextsResult is postBatchResult plus the optional hint array. Hints are
// dropped when every entry is blank so the serialized body — and therefore the
// engine's cache key — is unchanged for un-hinted batches.
func (c *Client) postBatchWithContextsResult(
	ctx context.Context,
	url string,
	texts, contexts []string,
	sourceLang, targetLang string,
) ([]string, error) {
	hasHint := false
	for _, h := range contexts {
		if strings.TrimSpace(h) != "" {
			hasHint = true
			break
		}
	}
	if !hasHint {
		contexts = nil
	}
	payload, err := json.Marshal(batchRequest{
		Texts:      texts,
		Contexts:   contexts,
		SourceLang: sourceLang,
		TargetLang: targetLang,
	})
	if err != nil {
		return nil, fmt.Errorf("encode translation request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build translation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("translation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("translation upstream returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read translation response: %w", err)
	}
	// Envelope-tolerant decode. kielolearn-engine /internal/translate-batch
	// now wraps its response in the v3 {"data": …} envelope; kielo-models
	// opus-mt /api/v3/translations stays bare. UnwrapDataEnvelope peels a
	// sole-"data" object and passes bare bodies through unchanged, so this
	// decodes BOTH shapes. Pre-fix the bare json decoder read the enveloped
	// engine body as body.Translations=nil → len(translations) < len(texts)
	// → treated every Gemini-routed batch as a full-batch failure, so seam
	// callProvider returned source (never cached) and callers re-translated
	// on every request (convo scenario-detail localization burned a cold
	// 10-30s Gemini call per open). Same class as the v3-envelope consumer
	// regressions swept elsewhere.
	var body batchResponse
	if err := json.Unmarshal(httputil.UnwrapDataEnvelope(raw), &body); err != nil {
		return nil, fmt.Errorf("decode translation response: %w", err)
	}
	if len(body.Translations) < len(texts) {
		result := make([]string, len(texts))
		copy(result, body.Translations)
		return result, nil
	}
	return slices.Clone(body.Translations), nil
}

// URL returns the kielo-models opus-mt endpoint URL. Retained for
// callers that need to log/expose the dispatch URL (kielo-convo
// orchestrator startup banner). With Sweep EEE the URL only
// reflects the opus-mt path; the Gemini path lives on engineURL.
func (c *Client) URL() string {
	return fmt.Sprintf("%s/api/v3/translations", c.modelsURL)
}
