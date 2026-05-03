// singleton_envelope_wrapper.go: response middleware that wraps a 2xx JSON
// body in `{"data": ...}` if it's not already in canonical Singleton[T] /
// CursorPage[T] / canonical-error shape.
//
// Background (ADR-004 §4): the canonical single-object envelope is
// Singleton[T] = `{"data": <object>}`. After 5 rounds of v3 migration,
// roughly 40 mobile-bff endpoints still pass v1-shaped bodies through
// to the client unchanged — conversations transcripts, subscription
// info, KieloTV catalogs, search hits, etc. Each is a small refactor on
// the handler side, but per-handler migration would touch dozens of
// files for the same one-line change.
//
// This middleware closes the gap immediately: it intercepts JSON
// response bodies on 2xx paths and wraps them in `{"data": <body>}`
// when the body looks like an unwrapped object. Handlers that already
// emit the canonical shape (Singleton via `pagination.NewSingleton`,
// CursorPage via `pagination.CursorPage{}`, or any object that already
// has `data`/`items` at top level) pass through unchanged.
//
// Why a body-rewriting middleware vs. per-handler migration:
//   - One opt-in per route (registered as middleware on the v3 group or
//     specific handlers). No per-handler diff.
//   - Handlers that get refactored later to emit Singleton[T] natively
//     don't break — the wrapper detects the canonical shape and skips.
//   - Streaming handlers (SSE, binary audio) skip the wrap because they
//     write through Flush before the body completes; the captureWriter
//     here gracefully degrades to pass-through on first Flush.
//   - 4xx/5xx are skipped — those are owned by the canonical error
//     envelope rewriter (LegacyErrorEnvelopeRewriter).
//
// Constraints:
//   - Body must be valid JSON. Non-JSON content types pass through.
//   - Body must be a JSON object (not a primitive or array). Raw arrays
//     get wrapped as `{"data": [...]}` — valid Singleton, but suggests
//     the handler should switch to CursorPage[T].
//   - 204 No Content passes through (no body to wrap).
//   - Already-canonical bodies (top-level `data`, `items`, or `error`)
//     pass through unchanged.

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// SingletonEnvelopeWrapper returns Echo middleware that wraps 2xx JSON
// bodies in `{"data": ...}` when not already in canonical envelope shape.
//
// See package doc for the rationale and contract.
func SingletonEnvelopeWrapper() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rec := newSingletonCaptureWriter(c.Response().Writer)
			c.Response().Writer = rec

			handlerErr := next(c)
			if handlerErr != nil {
				// Bubble up to Echo's HTTPErrorHandler — error path
				// goes through the canonical error envelope rewriter.
				c.Response().Writer = rec.original
				rec.flush()
				return handlerErr
			}

			status := rec.status
			// Only consider 2xx with a JSON body. 1xx/3xx/4xx/5xx pass
			// through (errors are handled by LegacyErrorEnvelopeRewriter).
			if status < 200 || status >= 300 {
				rec.flush()
				return nil
			}
			// 204 has no body to wrap.
			if status == http.StatusNoContent || rec.buf.Len() == 0 {
				rec.flush()
				return nil
			}
			ct := rec.header.Get(echo.HeaderContentType)
			if !strings.HasPrefix(strings.ToLower(ct), echo.MIMEApplicationJSON) {
				rec.flush()
				return nil
			}
			// First flush already happened (streaming) — body is gone.
			if rec.streamed {
				rec.flush()
				return nil
			}

			body := rec.buf.Bytes()
			wrapped, ok := maybeWrapAsSingleton(body)
			if !ok {
				rec.flush()
				return nil
			}

			// Replace buffer with wrapped body, fix Content-Length, and flush.
			rec.buf.Reset()
			rec.buf.Write(wrapped)
			rec.header.Set(echo.HeaderContentLength, "")
			rec.flush()
			return nil
		}
	}
}

// maybeWrapAsSingleton inspects the body and returns the wrapped body
// (along with ok=true) only when wrapping is appropriate. Returns
// ok=false for already-canonical or non-object bodies — the caller passes
// through.
func maybeWrapAsSingleton(body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	switch trimmed[0] {
	case '{':
		// Object — check for canonical top-level keys.
	case '[':
		// Bare array — wrap as {"data": [...]}. v3 lists should use
		// CursorPage[T]; this is a transitional shim.
		out, err := json.Marshal(map[string]json.RawMessage{
			"data": json.RawMessage(trimmed),
		})
		if err != nil {
			return nil, false
		}
		return out, true
	default:
		// Primitive (string, number, bool, null) — wrap as Singleton.
		out, err := json.Marshal(map[string]json.RawMessage{
			"data": json.RawMessage(trimmed),
		})
		if err != nil {
			return nil, false
		}
		return out, true
	}

	// Object case: detect canonical envelope shapes.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &top); err != nil {
		// Malformed JSON — pass through (let the client see whatever
		// the handler wrote; we don't want to make a bad situation worse).
		return nil, false
	}

	// Already canonical: Singleton[T] (`data`), CursorPage[T] (`items`),
	// or canonical error envelope (`error`). Pass through.
	if _, ok := top["data"]; ok {
		return nil, false
	}
	if _, ok := top["items"]; ok {
		return nil, false
	}
	if _, ok := top["error"]; ok {
		return nil, false
	}

	// Wrap the object as {"data": <object>}.
	out, err := json.Marshal(map[string]json.RawMessage{
		"data": json.RawMessage(trimmed),
	})
	if err != nil {
		return nil, false
	}
	return out, true
}

// singletonCaptureWriter — captures writes until flush() so we can inspect
// and optionally wrap the body before the client sees it. Mirrors the
// pattern in error_envelope_rewriter.go::captureWriter; can't reuse that
// type directly because it's unexported.
type singletonCaptureWriter struct {
	original    http.ResponseWriter
	header      http.Header
	buf         bytes.Buffer
	status      int
	wroteHeader bool
	flushed     bool
	streamed    bool
}

func newSingletonCaptureWriter(w http.ResponseWriter) *singletonCaptureWriter {
	return &singletonCaptureWriter{
		original: w,
		header:   w.Header(),
		status:   http.StatusOK,
	}
}

func (cw *singletonCaptureWriter) Header() http.Header { return cw.header }

func (cw *singletonCaptureWriter) WriteHeader(status int) {
	if cw.wroteHeader {
		return
	}
	cw.wroteHeader = true
	cw.status = status
}

func (cw *singletonCaptureWriter) Write(p []byte) (int, error) {
	if cw.streamed {
		return cw.original.Write(p)
	}
	return cw.buf.Write(p)
}

// flush replays the captured response. Idempotent.
func (cw *singletonCaptureWriter) flush() {
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

// Flush implements http.Flusher. SSE / streaming handlers call Flush
// after each event; on first call we flush the buffered data and switch
// to pass-through so subsequent writes don't get wrapped (a streaming
// body is by construction not a single JSON object).
func (cw *singletonCaptureWriter) Flush() {
	if !cw.streamed {
		cw.flush()
		cw.streamed = true
	}
	if f, ok := cw.original.(http.Flusher); ok {
		f.Flush()
	}
}
