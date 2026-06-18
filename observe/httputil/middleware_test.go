package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/observe"
	observelog "github.com/team-kielo-app/kielo-shared/observe/log"
	"github.com/team-kielo-app/kielo-shared/observe/pubsubutil"
)

func newTestContext(path string, headers http.Header) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestRequestTracing_CreatesNewTrace(t *testing.T) {
	c, rec := newTestContext("/test", nil)

	handler := RequestTracing()(func(c echo.Context) error {
		tc, ok := observe.FromContext(c.Request().Context())
		if !ok {
			t.Fatal("TraceContext not in stdlib context")
		}
		if tc.TraceID == "" {
			t.Error("TraceID should be generated")
		}
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatal(err)
	}

	if rec.Header().Get("Traceparent") == "" {
		t.Error("response should have Traceparent header")
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("response should have X-Request-Id header")
	}
}

func TestRequestTracing_ParsesTraceparent(t *testing.T) {
	h := http.Header{}
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	c, _ := newTestContext("/test", h)

	handler := RequestTracing()(func(c echo.Context) error {
		tc, _ := observe.FromContext(c.Request().Context())
		if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Errorf("TraceID = %q, want original", tc.TraceID)
		}
		if tc.SpanID == "00f067aa0ba902b7" {
			t.Error("SpanID should be a new child span, not the incoming one")
		}
		if tc.ParentSpanID != "00f067aa0ba902b7" {
			t.Errorf("ParentSpanID = %q, want incoming span ID", tc.ParentSpanID)
		}
		return nil
	})

	if err := handler(c); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTracing_FallsBackToClientTraceId(t *testing.T) {
	h := http.Header{}
	h.Set("X-Client-Trace-Id", "my-mobile-trace")
	c, _ := newTestContext("/test", h)

	handler := RequestTracing()(func(c echo.Context) error {
		tc, _ := observe.FromContext(c.Request().Context())
		if tc.TraceID == "" {
			t.Error("TraceID should be derived from X-Client-Trace-Id")
		}
		return nil
	})

	if err := handler(c); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTracing_StoresInEchoContext(t *testing.T) {
	c, _ := newTestContext("/test", nil)

	handler := RequestTracing()(func(c echo.Context) error {
		tc, ok := TraceFromEcho(c)
		if !ok {
			t.Fatal("TraceContext not in Echo context")
		}
		if tc.TraceID == "" {
			t.Error("TraceID should be set")
		}
		return nil
	})

	if err := handler(c); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTracing_PicksUpDownstreamCtxSwap(t *testing.T) {
	c, rec := newTestContext("/test", nil)

	producerTraceID := "0af7651916cd43dd8448eb211c80319c"
	producerSpanID := "b7ad6b7169203331"

	// Simulate downstream-middleware ctx swap: RequestTracing wraps
	// the handler. The handler itself stands in for a hypothetical
	// PushHandlerMiddleware that swaps the ctx with a different
	// TraceContext (extracted from PubSub message attributes in real
	// life).
	handler := RequestTracing()(func(c echo.Context) error {
		origTC, ok := observe.FromContext(c.Request().Context())
		if !ok {
			t.Fatal("RequestTracing did not set a TraceContext on the request ctx")
		}
		if origTC.TraceID == producerTraceID {
			t.Fatal("test setup error: RequestTracing accidentally produced the swapped TraceID")
		}

		newCtx := pubsubutil.ConsumerContext(c.Request().Context(), map[string]string{
			"trace_id": producerTraceID,
			"span_id":  producerSpanID,
		})
		c.SetRequest(c.Request().WithContext(newCtx))

		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatal(err)
	}

	respTraceparent := rec.Header().Get("Traceparent")
	if respTraceparent == "" {
		t.Fatal("response should have Traceparent header")
	}
	parts := strings.Split(respTraceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("response Traceparent = %q, want W3C-shaped header", respTraceparent)
	}
	if parts[1] != producerTraceID {
		t.Errorf("response trace_id = %q, want producer trace_id %q", parts[1], producerTraceID)
	}
	if parts[2] == producerSpanID {
		t.Errorf("response span_id = %q, want fresh consumer child span", parts[2])
	}
}

func TestRequestLogger_StatusLevels(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantLevel string
	}{
		{"2xx_info", 200, "INFO"},
		{"4xx_warn", 404, "WARN"},
		{"5xx_error", 500, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := observelog.New("test", observelog.WithOutput(&buf), observelog.WithLevel(slog.LevelDebug))

			c, _ := newTestContext("/test", nil)

			// Set up trace context first
			tc := observe.New()
			ctx := observe.WithContext(c.Request().Context(), tc)
			c.SetRequest(c.Request().WithContext(ctx))

			handler := RequestLogger(logger)(func(c echo.Context) error {
				c.Response().Status = tt.status
				return nil
			})

			_ = handler(c)

			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
			}
			if entry["level"] != tt.wantLevel {
				t.Errorf("level = %v, want %s", entry["level"], tt.wantLevel)
			}
		})
	}
}

func TestRequestLogger_IncludesTraceFields(t *testing.T) {
	var buf bytes.Buffer
	logger := observelog.New("test", observelog.WithOutput(&buf))

	c, _ := newTestContext("/api/v1/test", nil)
	tc := observe.New()
	ctx := observe.WithContext(c.Request().Context(), tc)
	c.SetRequest(c.Request().WithContext(ctx))

	handler := RequestLogger(logger)(func(c echo.Context) error {
		return c.String(200, "ok")
	})
	_ = handler(c)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	for _, field := range []string{"trace_id", "span_id", "request_id", "method", "path", "status", "duration_ms"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("missing field %q in log entry", field)
		}
	}
	if entry["trace_id"] != tc.TraceID {
		t.Errorf("trace_id = %v, want %s", entry["trace_id"], tc.TraceID)
	}
	if entry["path"] != "/api/v1/test" {
		t.Errorf("path = %v", entry["path"])
	}
}
