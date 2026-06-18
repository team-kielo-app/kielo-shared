package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// TestRewriter_LegacyShape_Upgraded — the core gap-closing case. A handler
// that emits the legacy `{"error":"msg"}` body on a 4xx now produces the
// canonical envelope downstream of the middleware.
func TestRewriter_LegacyShape_Upgraded(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/legacy", func(c echo.Context) error {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "word required"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/legacy", nil)
	// Inject a trace context so we can pin trace_id propagation.
	tc := observe.TraceContext{TraceID: "abcdef0123456789abcdef0123456789", SpanID: "1234567890abcdef"}
	req = req.WithContext(observe.WithContext(req.Context(), tc))
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body decode: %v; raw=%s", err, rec.Body.String())
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("error should be object, got %T (raw=%s)", body["error"], rec.Body.String())
	}
	if errObj["code"] != "BAD_REQUEST" {
		t.Errorf("error.code: want BAD_REQUEST, got %v", errObj["code"])
	}
	if errObj["message"] != "word required" {
		t.Errorf("error.message: want %q, got %v", "word required", errObj["message"])
	}
	if errObj["trace_id"] != "abcdef0123456789abcdef0123456789" {
		t.Errorf("error.trace_id: want injected id, got %v", errObj["trace_id"])
	}
	// Top-level message kept for back-compat.
	if body["message"] != "word required" {
		t.Errorf("message: want %q, got %v", "word required", body["message"])
	}
}

// TestRewriter_AlreadyCanonical_PassThrough — a handler that already
// emitted the canonical shape (via APIError or echo.NewHTTPError) MUST
// NOT be modified. Idempotent.
func TestRewriter_AlreadyCanonical_PassThrough(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/canonical", func(c echo.Context) error {
		return APIError(c, http.StatusNotFound, "NOT_FOUND", "thing missing", map[string]any{"id": "abc"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/canonical", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: want 404, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "NOT_FOUND" {
		t.Errorf("code preserved: got %v", errObj["code"])
	}
	details, _ := errObj["details"].(map[string]any)
	if details["id"] != "abc" {
		t.Errorf("details preserved: got %v", details)
	}
}

// TestRewriter_TwoXX_PassThrough — only 4xx/5xx are rewritten. 200
// responses must pass through verbatim.
func TestRewriter_TwoXX_PassThrough(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/ok", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"data": "fine", "error": "this should NOT be rewritten"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"this should NOT be rewritten"`) {
		t.Errorf("2xx body modified: %s", rec.Body.String())
	}
}

// TestRewriter_ExtrasFoldedIntoDetails — handlers like the FEATURE_LIMIT_REACHED
// pre-migration shape attach top-level keys siblings of `error`. The
// rewriter must fold those into `error.details` so nothing's dropped.
func TestRewriter_ExtrasFoldedIntoDetails(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/extras", func(c echo.Context) error {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"error":   "feature limit",
			"feature": "word_fetch_daily",
			"used":    11,
		})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/extras", nil)
	e.ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	errObj := body["error"].(map[string]any)
	details, ok := errObj["details"].(map[string]any)
	if !ok {
		t.Fatalf("details missing; envelope=%v", errObj)
	}
	if details["feature"] != "word_fetch_daily" {
		t.Errorf("details.feature: got %v", details["feature"])
	}
	if details["used"].(float64) != 11 {
		t.Errorf("details.used: got %v", details["used"])
	}
}

// TestRewriter_NonJSONPassthrough — bodies with non-JSON Content-Type
// (HTML, plain text, SSE) must NOT be parsed or rewritten.
func TestRewriter_NonJSONPassthrough(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/html", func(c echo.Context) error {
		return c.HTML(http.StatusBadRequest, "<h1>Bad Request</h1>")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/html", nil)
	e.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "<h1>Bad Request</h1>") {
		t.Errorf("html body modified: %s", rec.Body.String())
	}
}

// TestRewriter_NoErrorKey_PassThrough — a 4xx body without an "error"
// key (e.g. {"detail":"FastAPI-style"} forwarded by a Go proxy) is
// not the legacy shape and must pass through.
func TestRewriter_NoErrorKey_PassThrough(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/detail-shape", func(c echo.Context) error {
		return c.JSON(http.StatusBadRequest, map[string]string{"detail": "fastapi-style"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/detail-shape", nil)
	e.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"detail":"fastapi-style"`) {
		t.Errorf("detail-shape modified unexpectedly: %s", rec.Body.String())
	}
}

// TestRewriter_TraceIDFromContext — trace_id pulled from observe.TraceContext.
func TestRewriter_TraceIDFromContext(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/trace", func(c echo.Context) error {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "boom"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/trace", nil)
	tc := observe.TraceContext{TraceID: "0011223344556677889900aabbccddee", SpanID: "abcdefabcdef0011"}
	req = req.WithContext(observe.WithContext(context.Background(), tc))
	e.ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	errObj := body["error"].(map[string]any)
	if errObj["trace_id"] != "0011223344556677889900aabbccddee" {
		t.Errorf("trace_id: got %v", errObj["trace_id"])
	}
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("code: got %v", errObj["code"])
	}
}

// TestRewriter_FlushSwitchesToPassThroughAndStreams pins the SSE/streaming
// invariant: once a handler calls Flush(), subsequent Write calls must
// reach the wire (not get buffered into cw.buf). Without the pass-through
// switch the second SSE frame would sit in the buffer until request end —
// breaking real-time streaming for any handler routed through this
// middleware. Mirrors the same fix shipped on the Idempotency wrapper.
func TestRewriter_FlushSwitchesToPassThroughAndStreams(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/sse", func(c echo.Context) error {
		c.Response().Header().Set("Content-Type", "text/event-stream")
		c.Response().WriteHeader(http.StatusOK)
		_, _ = c.Response().Write([]byte("event: first\ndata: a\n\n"))
		c.Response().Flush()
		// This second frame is the one that would silently buffer
		// without the pass-through fix.
		_, _ = c.Response().Write([]byte("event: second\ndata: b\n\n"))
		c.Response().Flush()
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "data: a") {
		t.Errorf("first frame missing from body: %q", body)
	}
	if !strings.Contains(body, "data: b") {
		t.Errorf("second frame (post-flush) missing from body — pass-through switch broken: %q", body)
	}
}

// TestRewriter_StreamedResponseSkipsRewrite confirms the rewriter
// doesn't try to inspect/rewrite a body that's already streamed to the
// wire — passThrough should short-circuit the legacy-shape detection
// in the outer middleware.
func TestRewriter_StreamedResponseSkipsRewrite(t *testing.T) {
	e := echo.New()
	e.Use(LegacyErrorEnvelopeRewriter())
	e.GET("/sse-error", func(c echo.Context) error {
		c.Response().Header().Set("Content-Type", "application/json")
		c.Response().WriteHeader(http.StatusBadRequest)
		// Stream a legacy-looking body; rewriter MUST NOT touch it
		// once we've flushed (we can't unwrite bytes already on the
		// wire).
		_, _ = c.Response().Write([]byte(`{"error":"already streamed"}`))
		c.Response().Flush()
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/sse-error", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// The body should be the original legacy shape, NOT the canonical
	// envelope — because the rewriter saw passThrough and bailed.
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"already streamed"`) {
		t.Errorf("expected legacy body untouched after stream, got: %q", body)
	}
	// Specifically: NO "code" field added (that would mean the
	// rewriter tried to upgrade and probably appended a second JSON
	// payload after the streamed bytes).
	if strings.Contains(body, `"code"`) {
		t.Errorf("rewriter appended canonical envelope after streamed body: %q", body)
	}
}
