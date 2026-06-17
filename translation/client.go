package translation

import (
	"bytes"
	"context"
	"encoding/json"
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
	if !c.IsAvailable() || len(texts) == 0 {
		return nil
	}

	backend := SelectTranslatorBatch(sourceLang, targetLang, texts)
	switch backend {
	case BackendPassthrough:
		return slices.Clone(texts)
	case BackendOpusMT:
		return c.dispatchOpusMT(ctx, texts, sourceLang, targetLang)
	case BackendGemini:
		return c.dispatchGemini(ctx, texts, sourceLang, targetLang)
	default:
		return nil
	}
}

// dispatchOpusMT POSTs to kielo-models /api/v3/translations. Returns
// nil on misconfiguration / network error so the caller can fall
// back to source text.
func (c *Client) dispatchOpusMT(ctx context.Context, texts []string, sourceLang, targetLang string) []string {
	if strings.TrimSpace(c.modelsURL) == "" {
		// EEE routed here but models URL is missing — degrade by
		// returning nil so the caller passes through source text.
		return nil
	}
	return c.postBatch(ctx, c.modelsURL+"/api/v3/translations", texts, sourceLang, targetLang)
}

// dispatchGemini POSTs to kielolearn-engine /internal/translate-batch.
// Same payload + response shape as opus-mt so the wire format is
// uniform across backends.
func (c *Client) dispatchGemini(ctx context.Context, texts []string, sourceLang, targetLang string) []string {
	if strings.TrimSpace(c.engineURL) == "" {
		// EEE routed here but engine URL is missing — degrade.
		return nil
	}
	return c.postBatch(ctx, c.engineURL+"/internal/translate-batch", texts, sourceLang, targetLang)
}

// postBatch sends the wire-uniform translation batch request and
// decodes the standard {"translations": [...]} response. Internal
// helper shared by the two backend dispatch functions so the HTTP
// plumbing isn't duplicated.
func (c *Client) postBatch(ctx context.Context, url string, texts []string, sourceLang, targetLang string) []string {
	payload, err := json.Marshal(batchRequest{
		Texts:      texts,
		SourceLang: sourceLang,
		TargetLang: targetLang,
	})
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
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
		return nil
	}
	if len(body.Translations) < len(texts) {
		result := make([]string, len(texts))
		copy(result, body.Translations)
		return result
	}
	return slices.Clone(body.Translations)
}

// URL returns the kielo-models opus-mt endpoint URL. Retained for
// callers that need to log/expose the dispatch URL (kielo-convo
// orchestrator startup banner). With Sweep EEE the URL only
// reflects the opus-mt path; the Gemini path lives on engineURL.
func (c *Client) URL() string {
	return fmt.Sprintf("%s/api/v3/translations", c.modelsURL)
}
