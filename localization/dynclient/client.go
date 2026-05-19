// Package dynclient is the Go HTTP client for kielo-localization's
// dynamic_translations surface (ADR-012 §D2.6 Phase 2). It is the
// replacement for direct SQL writes to
// localization.dynamic_translations that previously lived in
// each writer service.
//
// Migration shape:
//
//	Before: writer service uses a pgxpool.Pool, runs an
//	        INSERT ... ON CONFLICT ... statement against
//	        localization.dynamic_translations directly.
//	After:  writer service holds a *dynclient.Client, calls
//	        Upsert() / FetchByResources() — kielo-localization
//	        runs the SQL inside its own schema.
//
// The client is intentionally tiny: no caching, no retries
// beyond the underlying httputil.Client's defaults, no batch
// merging. Callers that need batching loop over Upsert; callers
// that need caching wrap with their own seam-cache. The point
// is a thin translation of the existing repo-shaped API onto an
// HTTP transport so the cutover diff in each writer is minimal.
package dynclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/team-kielo-app/kielo-shared/observe/httputil"
)

// DefaultTimeout is the per-request timeout when the caller
// doesn't supply a custom *http.Client. Matches kielo-shared's
// other internal HTTP clients (translation, etc.).
const DefaultTimeout = 30 * time.Second

// DynamicTranslation mirrors kielo-localization's
// models.DynamicTranslation 1:1 — JSON tags match the wire
// shape. Duplicated here so callers don't need to import
// kielo-localization for the type (cross-service coupling).
//
// Keep this struct in sync with
// kielo-localization/internal/models/localization.go.
type DynamicTranslation struct {
	ID               uuid.UUID  `json:"id"`
	ResourceType     string     `json:"resource_type"`
	ResourceID       string     `json:"resource_id"`
	SourceVersion    string     `json:"source_version"`
	LanguageCode     string     `json:"language_code"`
	TranslatedText   string     `json:"translated_text"`
	Status           string     `json:"status"`
	SourceLocale     *string    `json:"source_locale,omitempty"`
	TranslatorSource *string    `json:"translator_source,omitempty"`
	ReviewedBy       *uuid.UUID `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Client is a thin HTTP wrapper around kielo-localization's
// dynamic_translations endpoints. Safe to share across
// goroutines.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New builds a client pointed at baseURL with the supplied
// internal API key. baseURL should be the root URL of
// kielo-localization (e.g. "http://kielo-localization:8080");
// the /internal/api/v3 prefix is added by the client.
//
// httpClient may be nil — defaults to httputil.NewClient with
// DefaultTimeout, matching the convention of other kielo-shared
// HTTP clients. Pass your own client to override timeout /
// transport (e.g. for tests).
func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = httputil.NewClient(DefaultTimeout)
	}
	return &Client{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

// UpsertRequest is the inbound POST /dynamic body. Field names
// match the column names in localization.dynamic_translations.
//
// SourceVersion is caller-supplied (typically
// localization.SourceVersionFromText(englishSourceText)). Status
// and TranslatorSource default to "machine" / "lazy_translation"
// at the service level when empty — callers can leave them
// blank for the common machine-write case.
//
// ReviewerID is the admin user attributing the write (for
// audit). Pass uuid.Nil for machine writes / bulk imports.
type UpsertRequest struct {
	ResourceType     string    `json:"resource_type"`
	ResourceID       string    `json:"resource_id"`
	SourceVersion    string    `json:"source_version"`
	LanguageCode     string    `json:"language_code"`
	TranslatedText   string    `json:"translated_text"`
	Status           string    `json:"status,omitempty"`
	SourceLocale     string    `json:"source_locale,omitempty"`
	TranslatorSource string    `json:"translator_source,omitempty"`
	ReviewerID       uuid.UUID `json:"reviewer_id,omitempty"`
}

// UpsertResponse wraps the row + the inserted/updated flag
// (xmax = 0 idiom on the service-side RETURNING). Callers that
// don't care which path it took can ignore the bool.
type UpsertResponse struct {
	Row      *DynamicTranslation `json:"row"`
	Inserted bool                `json:"inserted"`
}

// Upsert posts one row. Returns the persisted row + a bool that
// distinguishes a fresh insert from an update on an existing
// row. ctx deadlines are honored by the underlying http.Client.
func (c *Client) Upsert(ctx context.Context, req UpsertRequest) (*UpsertResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("dynclient: nil client")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal upsert request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/internal/api/v3/localization/dynamic",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("build upsert request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upsert dynamic_translation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.statusErr(resp, "upsert")
	}
	var out UpsertResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode upsert response: %w", err)
	}
	return &out, nil
}

// FetchRequest is the inbound POST /dynamic/fetch body.
// ResourceTypes constrains the resource_type column (e.g.
// {"scenario.title", "scenario.description"}). ResourceIDs
// constrains the resource_id column (UUID strings or arbitrary
// TEXT keys depending on the resource type).
type FetchRequest struct {
	ResourceTypes []string `json:"resource_types"`
	ResourceIDs   []string `json:"resource_ids"`
}

// FetchResponse is the {items: [...]} list returned by the
// fetch endpoint. One row per (resource_type, resource_id,
// language_code) tuple — DISTINCT ON ordering keeps the freshest
// visible row.
type FetchResponse struct {
	Items []DynamicTranslation `json:"items"`
}

// FetchByResources returns the freshest visible row per
// (resource_type, resource_id, language_code) tuple that
// matches the supplied filters. Empty filters return an empty
// list (service-side 400; this client surfaces the error).
func (c *Client) FetchByResources(ctx context.Context, req FetchRequest) (*FetchResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("dynclient: nil client")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal fetch request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/internal/api/v3/localization/dynamic/fetch",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("build fetch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch dynamic_translations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusErr(resp, "fetch")
	}
	var out FetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode fetch response: %w", err)
	}
	return &out, nil
}

// statusErr formats a non-2xx response into a useful error,
// including the response body up to a sane cap so accidental
// HTML error pages don't blow up the log.
func (c *Client) statusErr(resp *http.Response, op string) error {
	const maxBody = 512
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	bodyStr := strings.TrimSpace(string(body))
	if bodyStr == "" {
		return fmt.Errorf("dynclient: %s returned %d", op, resp.StatusCode)
	}
	return fmt.Errorf("dynclient: %s returned %d: %s", op, resp.StatusCode, bodyStr)
}
