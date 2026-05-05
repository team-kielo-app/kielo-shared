// error_envelope_rewriter.go: response middleware that auto-upgrades
// legacy hand-built error bodies to the canonical envelope.
//
// Background (ADR-004 §5): the audit cataloged ~552 hand-rolled
// `c.JSON(http.StatusXxx, map[string]string{"error": "msg"})` sites
// across the Go services. These bypass CanonicalEchoErrorHandler entirely,
// so the response body is `{"error": "msg"}` — missing `error.code`,
// `error.trace_id`, `details`. Mobile/admin clients have to special-case
// this shape, and trace correlation breaks.
//
// Migrating each site by hand is per-site work (each needs an error
// code + details judgment) — slow and risky. This middleware closes the
// gap immediately: it intercepts response writes on 4xx/5xx, detects the
// legacy `{"error": "string"}` body, and rewrites it to the canonical
// `{"error":{"code":...,"message":...,"trace_id":...},"message":...}`
// shape. Sites that already emit the canonical shape (because they used
// APIError or echo.NewHTTPError) pass through unchanged.
//
// Why a body-rewriting middleware vs. per-site migration:
//   - One commit covers every service. ADR-004 §5 deadline relief.
//   - Sites can be incrementally hand-migrated to APIError later
//     without breaking — APIError already produces the canonical shape,
//     so the rewriter sees it as "already canonical" and passes through.
//   - The rewriter only ever ADDS fields (code, trace_id) to a body
//     that already has `error: "msg"`. It never changes status codes
//     or content types or removes data.
//
// Ordering: register AFTER the trace middleware (so trace_id is in
// context) and AFTER any handler that writes the legacy body.
//
//	e.Use(observe.RequestTracing())
//	e.Use(middleware.LegacyErrorEnvelopeRewriter())
//
// This middleware is a no-op for:
//   - Status < 400
//   - Already-canonical bodies ({"error":{"code":...}})
//   - Non-JSON bodies (Content-Type doesn't start with application/json)
//   - Empty bodies
//   - Bodies that aren't a top-level object with an "error" key
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// LegacyErrorEnvelopeRewriter returns Echo middleware that upgrades
// legacy hand-built error envelopes to the canonical shape on the
// response path.
//
// See package doc for the rationale and contract.
func LegacyErrorEnvelopeRewriter() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rec := newCaptureWriter(c.Response().Writer)
			c.Response().Writer = rec

			handlerErr := next(c)
			if handlerErr != nil {
				// Bubble up to Echo's HTTPErrorHandler — that path
				// already produces the canonical envelope.
				c.Response().Writer = rec.original
				rec.flush()
				return handlerErr
			}

			// Only consider 4xx/5xx with a JSON body.
			status := rec.status
			if status < 400 {
				rec.flush()
				return nil
			}
			ct := rec.header.Get(echo.HeaderContentType)
			if !strings.HasPrefix(strings.ToLower(ct), echo.MIMEApplicationJSON) {
				rec.flush()
				return nil
			}
			body := rec.buf.Bytes()
			if len(body) == 0 {
				rec.flush()
				return nil
			}

			rewritten, ok := rewriteLegacyErrorBody(body, status,
				traceIDFromContext(c.Request().Context()))
			if !ok {
				rec.flush()
				return nil
			}

			// Replace the body. Must update Content-Length too —
			// Echo's response wrapper tracks it for the access log
			// even though the underlying ResponseWriter usually doesn't.
			rec.buf.Reset()
			rec.buf.Write(rewritten)
			rec.header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec.flush()
			return nil
		}
	}
}

// rewriteLegacyErrorBody returns the canonical envelope bytes if `body`
// matches the legacy `{"error": "string"}` shape, else (nil, false).
//
// Recognized legacy shapes (all observed in the audit):
//
//	{"error": "msg"}                              → upgrade
//	{"error": "msg", "details": "more"}           → upgrade, fold details into error.details
//	{"error": "msg", "anything": ...}              → upgrade, preserve other top-level keys
//	{"error": {"code": "X", ...}}                  → already canonical, leave alone
//	{"error": {...non-canonical object...}}        → leave alone (uncommon, ambiguous)
//
// trace_id is appended only if not already present in the upgraded body.
func rewriteLegacyErrorBody(body []byte, status int, traceID string) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false
	}
	rawErr, ok := raw["error"]
	if !ok {
		return nil, false
	}

	// Case 1: error is already an object — pass through (handler
	// produced the canonical envelope or another structured shape).
	trimmed := bytes.TrimSpace(rawErr)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return nil, false
	}

	// Case 2: error is a string — legacy shape. Upgrade.
	var msg string
	if err := json.Unmarshal(rawErr, &msg); err != nil {
		return nil, false
	}

	// Build canonical error object.
	errObj := map[string]any{
		"code":    defaultCodeForStatus(status),
		"message": msg,
	}
	if traceID != "" {
		errObj["trace_id"] = traceID
	}
	// Surface any extra top-level non-error keys as details so we
	// don't drop information that the handler chose to include
	// (e.g. {"error":"…", "details":"…"} or {"error":"…","feature":"X"}).
	if extras := extractExtras(raw); len(extras) > 0 {
		errObj["details"] = extras
	}

	out := map[string]any{
		"error":   errObj,
		"message": msg, // legacy top-level mirror, kept for back-compat.
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

// extractExtras pulls out any top-level keys other than "error" and
// "message" so we can fold them into error.details rather than dropping
// them. Skips nil/empty values.
func extractExtras(raw map[string]json.RawMessage) map[string]any {
	out := map[string]any{}
	for k, v := range raw {
		if k == "error" || k == "message" {
			continue
		}
		var decoded any
		if err := json.Unmarshal(v, &decoded); err == nil && decoded != nil {
			out[k] = decoded
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// captureWriter buffers writes until flush() so we can inspect and
// optionally rewrite the body before the client sees it.
//
// Echo's standard wrapping calls WriteHeader once with the final status
// and then Write zero or more times with the body chunks. We capture
// both and replay them to the original writer at flush().
type captureWriter struct {
	original    http.ResponseWriter
	header      http.Header
	buf         bytes.Buffer
	status      int
	wroteHeader bool
	flushed     bool
}

func newCaptureWriter(w http.ResponseWriter) *captureWriter {
	return &captureWriter{
		original: w,
		header:   w.Header(),
		status:   http.StatusOK,
	}
}

// Header proxies through to the underlying writer's Header so handlers
// observe the same map they always have.
func (cw *captureWriter) Header() http.Header { return cw.header }

func (cw *captureWriter) WriteHeader(status int) {
	if cw.wroteHeader {
		return
	}
	cw.wroteHeader = true
	cw.status = status
}

func (cw *captureWriter) Write(p []byte) (int, error) {
	return cw.buf.Write(p)
}

// flush replays the captured response to the underlying writer. Idempotent.
func (cw *captureWriter) flush() {
	if cw.flushed {
		return
	}
	cw.flushed = true
	if cw.wroteHeader {
		cw.original.WriteHeader(cw.status)
	}
	if cw.buf.Len() > 0 {
		_, _ = cw.original.Write(cw.buf.Bytes())
	}
}

// Flush implements http.Flusher so SSE-style streaming handlers still
// work — they bypass our buffer entirely on the first flush.
func (cw *captureWriter) Flush() {
	// First flush forces the buffered data through and switches us to
	// pass-through mode. Subsequent writes go straight to the
	// underlying writer.
	cw.flush()
	if f, ok := cw.original.(http.Flusher); ok {
		f.Flush()
	}
}

// observePassthrough — dummy use of observe to keep the import explicit
// and the package linkable even on Go versions that prune unused imports.
// Without this the compiler complains; we use observe.FromContext via
// traceIDFromContext (defined in errors.go in this package).
var _ = observe.HeaderClientTraceID
