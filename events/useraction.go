package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// UserActionEnvelope is the canonical ADR-011 §D2.2 wire shape every
// emitter POSTs to kielo-events. Mirrors
// kielo-events/internal/models/event.go but lives here because:
//
//  1. Emitter services link against kielo-shared, not kielo-events.
//  2. Duplicating the shape risks drift the cross-language contract
//     fixture would catch — single source of truth in Go land lives
//     here; kielo-events' decoder accepts this exact JSON.
//
// `user_id` is NOT a field — it travels in the X-User-ID header
// (matches kielo-events' IngestInternal handler contract).
type UserActionEnvelope struct {
	EventID       string         `json:"event_id"`
	EventType     string         `json:"event_type"`
	TS            time.Time      `json:"ts"`
	SchemaVersion int16          `json:"schema_version"`
	Props         map[string]any `json:"props"`
	Context       map[string]any `json:"context,omitempty"`
	// DerivedFrom points at the primary event_id when this envelope
	// is a server-emitted side-effect (per ADR-011 §D5). Omitted for
	// primary events. Subscribers MUST filter `derived_from != null`
	// from re-ingestion paths to prevent the spine from looping.
	// The spine's V066 schema persists this as a CHAR(26) FK to the
	// same events.user_actions table.
	DerivedFrom string `json:"derived_from,omitempty"`
}

// UserActionEmitter is the narrow interface emitter sites take.
// Tests inject a recording fake; production injects HTTPEmitter.
type UserActionEmitter interface {
	Emit(ctx context.Context, userID uuid.UUID, envelope UserActionEnvelope) error
}

// HTTPEmitter POSTs to kielo-events' internal route. Stateless +
// goroutine-safe; share a single instance across the process.
//
// Phase-2 graceful degradation: when EventsServiceURL is empty,
// Emit returns nil (no-op) so emitter callers can wire this up
// before kielo-events deploys without breaking their happy path.
type HTTPEmitter struct {
	EventsServiceURL string
	InternalAPIKey   string
	HTTPClient       *http.Client
	// SourceService stamps the X-Kielo-Source-Service header so
	// kielo-events logs which emitter produced each event. Not part
	// of the envelope's schema; observability only.
	SourceService string
}

// NewHTTPEmitter constructs an emitter with sensible defaults. A
// nil HTTPClient gets a 5s-timeout client (the kielo-events ingest
// path completes in <50ms in practice; 5s catches a stuck network).
func NewHTTPEmitter(eventsServiceURL, internalAPIKey, sourceService string, httpClient *http.Client) *HTTPEmitter {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &HTTPEmitter{
		EventsServiceURL: eventsServiceURL,
		InternalAPIKey:   internalAPIKey,
		HTTPClient:       httpClient,
		SourceService:    sourceService,
	}
}

// Emit POSTs the envelope to kielo-events. Returns nil on:
//   - empty EventsServiceURL (Phase-2 no-op fallback)
//   - kielo-events 2xx (success, including idempotent replay)
//
// Returns an error on:
//   - network failure
//   - kielo-events 4xx (validation failure — the emitter sent a bad event)
//   - kielo-events 5xx (transient; caller MAY retry)
//
// The envelope's EventID MUST be set by the caller; emitters are
// responsible for minting + persisting their idempotency keys so a
// retry within the spine's dedup window collapses to a single row.
// (events.NewULID is the standard generator.)
func (h *HTTPEmitter) Emit(ctx context.Context, userID uuid.UUID, envelope UserActionEnvelope) error {
	if h == nil || h.EventsServiceURL == "" {
		// Phase-2 fallback. Logged at the caller (emitter site)
		// rather than here so each emitter can tag the no-op with
		// its own context (article_version_id, etc).
		return nil
	}
	if envelope.EventID == "" {
		return errors.New("events.Emit: envelope.EventID must be set (use events.NewULID())")
	}
	if envelope.EventType == "" {
		return errors.New("events.Emit: envelope.EventType must be set")
	}
	if envelope.TS.IsZero() {
		envelope.TS = time.Now().UTC()
	}
	if envelope.SchemaVersion == 0 {
		envelope.SchemaVersion = 1
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("events.Emit: marshal envelope: %w", err)
	}

	url := h.EventsServiceURL + "/internal/api/v3/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("events.Emit: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(UserIDHeader, userID.String())
	if h.InternalAPIKey != "" {
		req.Header.Set("X-Internal-API-Key", h.InternalAPIKey)
	}
	if h.SourceService != "" {
		req.Header.Set("X-Kielo-Source-Service", h.SourceService)
	}

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("events.Emit: POST kielo-events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Drain the body so the connection can be reused (HTTP/1.1
		// keep-alive requires the body to be read in full).
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	// Non-2xx → surface the spine's error body to the caller so the
	// failure log is precise about which validation rule fired.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("events.Emit: kielo-events returned %d: %s",
		resp.StatusCode, string(respBody))
}

// NoOpEmitter is the dev/test no-emit implementation. Used by:
//   - main.go when EVENTS_SERVICE_URL is unset (Phase 2 fallback)
//   - tests that don't care about emitter side effects
type NoOpEmitter struct{}

func (NoOpEmitter) Emit(_ context.Context, _ uuid.UUID, _ UserActionEnvelope) error {
	return nil
}
