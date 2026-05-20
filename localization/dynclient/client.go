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
//
// ResourceIDPrefix supports the kielotv access pattern where the
// resource_id is a composite like `<videoID>.<cueIdx>`. The
// caller passes the prefix (`<videoID>.`) so the service does a
// LIKE scan rather than the client having to know the cue IDs
// upfront. Empty prefix is ignored; if both ResourceIDs and
// ResourceIDPrefix are supplied, the row must satisfy BOTH.
//
// LanguageCode is optional; empty means "all languages" (the
// convo scenario path needs every locale so the consumer can
// pick at render time).
//
// At least one of ResourceIDs or ResourceIDPrefix MUST be set —
// the service rejects (400) otherwise to prevent accidental
// full-table scans.
type FetchRequest struct {
	ResourceTypes    []string `json:"resource_types"`
	ResourceIDs      []string `json:"resource_ids,omitempty"`
	ResourceIDPrefix string   `json:"resource_id_prefix,omitempty"`
	LanguageCode     string   `json:"language_code,omitempty"`
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

// ============================================================================
// Admin write surface (ADR-012 §D2.6 Phase 2 cutover, 2026-05-19).
// Used by kielo-cms's localization admin handler to retire its
// direct SQL writes against localization.* tables.
// ============================================================================

// Language mirrors kielo-localization models.Language.
type Language struct {
	Code       string    `json:"code"`
	Name       string    `json:"name"`
	NativeName *string   `json:"native_name,omitempty"`
	Flag       *string   `json:"flag,omitempty"`
	Direction  string    `json:"direction"`
	IsDefault  bool      `json:"is_default"`
	IsActive   bool      `json:"is_active"`
	FallbackTo *string   `json:"fallback_to,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Namespace mirrors kielo-localization models.Namespace.
type Namespace struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	Platform    *string   `json:"platform,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateLanguageRequest matches kielo-localization's wire shape.
type CreateLanguageRequest struct {
	Code       string  `json:"code"`
	Name       string  `json:"name"`
	NativeName *string `json:"native_name,omitempty"`
	Flag       *string `json:"flag,omitempty"`
	Direction  string  `json:"direction"`
	IsDefault  bool    `json:"is_default"`
	IsActive   bool    `json:"is_active"`
	FallbackTo *string `json:"fallback_to,omitempty"`
}

// UpdateLanguageRequest matches kielo-localization's PATCH body.
type UpdateLanguageRequest struct {
	Name       string  `json:"name"`
	NativeName *string `json:"native_name,omitempty"`
	Flag       *string `json:"flag,omitempty"`
	Direction  string  `json:"direction"`
	IsDefault  bool    `json:"is_default"`
	IsActive   bool    `json:"is_active"`
	FallbackTo *string `json:"fallback_to,omitempty"`
}

// CreateNamespaceRequest matches kielo-localization's POST body.
type CreateNamespaceRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Platform    *string `json:"platform,omitempty"`
	IsActive    bool    `json:"is_active"`
}

// UpdateNamespaceRequest matches kielo-localization's PATCH body.
type UpdateNamespaceRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Platform    *string `json:"platform,omitempty"`
	IsActive    bool    `json:"is_active"`
}

// CreateLanguage POSTs to /languages. 409 (already exists) is
// returned as a wrapped DynClientError with status 409.
func (c *Client) CreateLanguage(ctx context.Context, req CreateLanguageRequest) (*Language, error) {
	var out Language
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/languages", req, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateLanguage PATCHes to /languages/:code. 404 is wrapped.
func (c *Client) UpdateLanguage(ctx context.Context, code string, req UpdateLanguageRequest) (*Language, error) {
	if code == "" {
		return nil, fmt.Errorf("dynclient: code required")
	}
	var out Language
	if err := c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/languages/"+code, req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateNamespace POSTs to /namespaces.
func (c *Client) CreateNamespace(ctx context.Context, req CreateNamespaceRequest) (*Namespace, error) {
	var out Namespace
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/namespaces", req, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateNamespace PATCHes to /namespaces/:id. 404 is wrapped.
func (c *Client) UpdateNamespace(ctx context.Context, id uuid.UUID, req UpdateNamespaceRequest) (*Namespace, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("dynclient: id required")
	}
	var out Namespace
	if err := c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/namespaces/"+id.String(), req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// DynClientHTTPError carries the upstream status code so callers
// can map 404 / 409 / 400 to caller-side sentinels (e.g.
// "language already exists" => 409). Embeds the body prefix for
// log debug.
type DynClientHTTPError struct {
	Op     string
	Status int
	Body   string
}

func (e *DynClientHTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("dynclient: %s returned %d", e.Op, e.Status)
	}
	return fmt.Sprintf("dynclient: %s returned %d: %s", e.Op, e.Status, e.Body)
}

// doJSON is the shared request helper used by the admin CRUD
// methods. POST/PATCH a JSON body, expect a specific success
// status, decode into out. Non-success returns a
// *DynClientHTTPError that callers can errors.As to inspect.
func (c *Client) doJSON(
	ctx context.Context,
	method, path string,
	body any,
	out any,
	expectStatus int,
) error {
	if c == nil {
		return fmt.Errorf("dynclient: nil client")
	}
	var reqBody io.Reader = http.NoBody
	hasBody := body != nil
	if hasBody {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectStatus {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &DynClientHTTPError{
			Op:     method + " " + path,
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(respBody)),
		}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// ============================================================================
// Translation keys, translations, bundles, audit_log, dynamic-status
// (ADR-012 §D2.6 Phase 2 cutover full admin slice).
// ============================================================================

// TranslationKeyPlaceholder mirrors models.TranslationKeyPlaceholder.
type TranslationKeyPlaceholder struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Example string `json:"example"`
}

// TranslationKey mirrors models.TranslationKey.
type TranslationKey struct {
	ID                   uuid.UUID                   `json:"id"`
	NamespaceID          uuid.UUID                   `json:"namespace_id"`
	Key                  string                      `json:"key"`
	Description          *string                     `json:"description,omitempty"`
	SourceText           string                      `json:"source_text"`
	Placeholders         []TranslationKeyPlaceholder `json:"placeholders,omitempty"`
	MaxLength            *int                        `json:"max_length,omitempty"`
	ContextScreenshotURL *string                     `json:"context_screenshot_url,omitempty"`
	Tags                 []string                    `json:"tags,omitempty"`
	CreatedBy            *uuid.UUID                  `json:"created_by,omitempty"`
	CreatedAt            time.Time                   `json:"created_at"`
	UpdatedAt            time.Time                   `json:"updated_at"`
}

// Translation mirrors models.Translation.
type Translation struct {
	ID               uuid.UUID  `json:"id"`
	KeyID            uuid.UUID  `json:"key_id"`
	LanguageCode     string     `json:"language_code"`
	Value            string     `json:"value"`
	Status           string     `json:"status"`
	QualityScore     *float64   `json:"quality_score,omitempty"`
	TranslatorSource *string    `json:"translator_source,omitempty"`
	ReviewedBy       *uuid.UUID `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// TranslationBundle mirrors models.TranslationBundle.
type TranslationBundle struct {
	ID           uuid.UUID         `json:"id"`
	NamespaceID  *uuid.UUID        `json:"namespace_id,omitempty"`
	LanguageCode string            `json:"language_code"`
	Bundle       map[string]string `json:"bundle"`
	Version      int               `json:"version"`
	Checksum     string            `json:"checksum"`
	GeneratedAt  time.Time         `json:"generated_at"`
}

// CreateTranslationKeyRequest matches the kielo-localization
// handler shape.
type CreateTranslationKeyRequest struct {
	NamespaceID          uuid.UUID                   `json:"namespace_id"`
	Key                  string                      `json:"key"`
	Description          *string                     `json:"description,omitempty"`
	SourceText           string                      `json:"source_text"`
	Placeholders         []TranslationKeyPlaceholder `json:"placeholders,omitempty"`
	MaxLength            *int                        `json:"max_length,omitempty"`
	ContextScreenshotURL *string                     `json:"context_screenshot_url,omitempty"`
	Tags                 []string                    `json:"tags,omitempty"`
	CreatedBy            *uuid.UUID                  `json:"created_by,omitempty"`
}

// UpdateTranslationKeyRequest matches PATCH /keys/:id body.
type UpdateTranslationKeyRequest struct {
	Description          *string                     `json:"description,omitempty"`
	SourceText           *string                     `json:"source_text,omitempty"`
	Placeholders         []TranslationKeyPlaceholder `json:"placeholders,omitempty"`
	MaxLength            *int                        `json:"max_length,omitempty"`
	ContextScreenshotURL *string                     `json:"context_screenshot_url,omitempty"`
	Tags                 []string                    `json:"tags,omitempty"`
}

// BulkCreateTranslationKeysRequest matches POST /keys/bulk body.
type BulkCreateTranslationKeysRequest struct {
	Keys      []CreateTranslationKeyRequest `json:"keys"`
	CreatedBy *uuid.UUID                    `json:"created_by,omitempty"`
}

// BulkCreateTranslationKeysResponse wraps the returned rows.
type BulkCreateTranslationKeysResponse struct {
	Items []TranslationKey `json:"items"`
}

// BulkUpdateKeySourceTextRequest matches PATCH /keys/bulk/source.
type BulkUpdateKeySourceTextRequest struct {
	Updates map[uuid.UUID]string `json:"updates"`
}

// CreateOrUpdateTranslationRequest matches POST /translations.
type CreateOrUpdateTranslationRequest struct {
	KeyID            uuid.UUID  `json:"key_id"`
	LanguageCode     string     `json:"language_code"`
	Value            string     `json:"value"`
	Status           *string    `json:"status,omitempty"`
	TranslatorSource *string    `json:"translator_source,omitempty"`
	QualityScore     *float64   `json:"quality_score,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
}

// BulkUpsertTranslationsItem matches the items in POST /translations/bulk.
type BulkUpsertTranslationsItem struct {
	KeyID            uuid.UUID `json:"key_id"`
	LanguageCode     string    `json:"language_code"`
	Value            string    `json:"value"`
	Status           string    `json:"status,omitempty"`
	TranslatorSource string    `json:"translator_source,omitempty"`
}

// BulkUpsertTranslationsRequest matches POST /translations/bulk.
type BulkUpsertTranslationsRequest struct {
	Items     []BulkUpsertTranslationsItem `json:"items"`
	CreatedBy *uuid.UUID                   `json:"created_by,omitempty"`
}

// SetTranslationStatusRequest matches PATCH /translations/:id/status.
type SetTranslationStatusRequest struct {
	Status     string     `json:"status"`
	ReviewedBy *uuid.UUID `json:"reviewed_by,omitempty"`
}

// CreateAuditLogRequest matches POST /audit. OldValue / NewValue
// are typed as `any` so callers can pass arbitrary diff shapes —
// the kielo-localization side stores them as opaque jsonb.
type CreateAuditLogRequest struct {
	EntityType  string     `json:"entity_type"`
	EntityID    uuid.UUID  `json:"entity_id"`
	Action      string     `json:"action"`
	OldValue    any        `json:"old_value,omitempty"`
	NewValue    any        `json:"new_value,omitempty"`
	PerformedBy *uuid.UUID `json:"performed_by,omitempty"`
	IPAddress   *string    `json:"ip_address,omitempty"`
	UserAgent   *string    `json:"user_agent,omitempty"`
}

// SetDynamicTranslationStatusRequest matches PATCH /dynamic/:id/status.
type SetDynamicTranslationStatusRequest struct {
	Status       string    `json:"status"`
	ReviewedBy   uuid.UUID `json:"reviewed_by,omitempty"`
	OverrideText string    `json:"override_text,omitempty"`
}

// CreateTranslationKey POSTs to /keys.
func (c *Client) CreateTranslationKey(ctx context.Context, req CreateTranslationKeyRequest) (*TranslationKey, error) {
	var out TranslationKey
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/keys", req, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateTranslationKey PATCHes /keys/:id.
func (c *Client) UpdateTranslationKey(ctx context.Context, id uuid.UUID, req UpdateTranslationKeyRequest) error {
	return c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/keys/"+id.String(), req, nil, http.StatusNoContent)
}

// DeleteTranslationKey DELETEs /keys/:id.
func (c *Client) DeleteTranslationKey(ctx context.Context, id uuid.UUID) error {
	return c.doJSON(ctx, http.MethodDelete, "/internal/api/v3/localization/keys/"+id.String(), nil, nil, http.StatusNoContent)
}

// BulkCreateTranslationKeys POSTs to /keys/bulk.
func (c *Client) BulkCreateTranslationKeys(ctx context.Context, req BulkCreateTranslationKeysRequest) (*BulkCreateTranslationKeysResponse, error) {
	var out BulkCreateTranslationKeysResponse
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/keys/bulk", req, &out, http.StatusCreated); err != nil {
		return nil, err
	}
	return &out, nil
}

// BulkUpdateKeySourceText PATCHes /keys/bulk/source.
func (c *Client) BulkUpdateKeySourceText(ctx context.Context, req BulkUpdateKeySourceTextRequest) error {
	return c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/keys/bulk/source", req, nil, http.StatusNoContent)
}

// CreateOrUpdateTranslation POSTs to /translations.
func (c *Client) CreateOrUpdateTranslation(ctx context.Context, req CreateOrUpdateTranslationRequest) (*Translation, error) {
	var out Translation
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/translations", req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// BulkUpsertTranslations POSTs to /translations/bulk.
func (c *Client) BulkUpsertTranslations(ctx context.Context, req BulkUpsertTranslationsRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/translations/bulk", req, nil, http.StatusNoContent)
}

// SetTranslationStatus PATCHes /translations/:id/status.
func (c *Client) SetTranslationStatus(ctx context.Context, id uuid.UUID, req SetTranslationStatusRequest) error {
	return c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/translations/"+id.String()+"/status", req, nil, http.StatusNoContent)
}

// GenerateBundle POSTs to /bundles/:namespace_id/:lang/generate.
func (c *Client) GenerateBundle(ctx context.Context, namespaceID uuid.UUID, languageCode string) (*TranslationBundle, error) {
	var out TranslationBundle
	if err := c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/bundles/"+namespaceID.String()+"/"+languageCode+"/generate", struct{}{}, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateAuditLog POSTs to /audit.
func (c *Client) CreateAuditLog(ctx context.Context, req CreateAuditLogRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/internal/api/v3/localization/audit", req, nil, http.StatusNoContent)
}

// SetDynamicTranslationStatus PATCHes /dynamic/:id/status.
// Returns the updated row so callers can scope cache
// invalidation by resource_type.
func (c *Client) SetDynamicTranslationStatus(ctx context.Context, id uuid.UUID, req SetDynamicTranslationStatusRequest) (*DynamicTranslation, error) {
	var out DynamicTranslation
	if err := c.doJSON(ctx, http.MethodPatch, "/internal/api/v3/localization/dynamic/"+id.String()+"/status", req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// doJSONWithDelete is a tiny aux so DELETE with no body doesn't
// marshal a "null" payload — net/http and the service handle it
// fine, but emitting `null` as the body is unusual.
// (kept inline within doJSON; this aux note explains the
// nil-body branch.)
