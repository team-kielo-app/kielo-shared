package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
)

// TestSingletonEnvelopeWrapper pins the wrap-vs-pass-through decision
// for every body shape the v3 surface emits.
func TestSingletonEnvelopeWrapper(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantBody string
	}{
		{
			name:     "object passthrough is wrapped",
			status:   200,
			body:     `{"id":"abc","name":"x"}`,
			wantBody: `{"data":{"id":"abc","name":"x"}}`,
		},
		{
			name:     "already-canonical Singleton passes through",
			status:   200,
			body:     `{"data":{"id":"abc"}}`,
			wantBody: `{"data":{"id":"abc"}}`,
		},
		{
			name:     "already-canonical CursorPage passes through",
			status:   200,
			body:     `{"items":[{"id":"abc"}],"next_page_key":""}`,
			wantBody: `{"items":[{"id":"abc"}],"next_page_key":""}`,
		},
		{
			name:     "canonical error passes through",
			status:   200,
			body:     `{"error":{"code":"X","message":"y"}}`,
			wantBody: `{"error":{"code":"X","message":"y"}}`,
		},
		{
			name:     "bare array gets wrapped",
			status:   200,
			body:     `[{"id":"abc"}]`,
			wantBody: `{"data":[{"id":"abc"}]}`,
		},
		{
			name:     "primitive number wrapped",
			status:   200,
			body:     `42`,
			wantBody: `{"data":42}`,
		},
		{
			name:     "4xx passes through (handled by error rewriter)",
			status:   400,
			body:     `{"error":"bad"}`,
			wantBody: `{"error":"bad"}`,
		},
		{
			name:     "5xx passes through",
			status:   500,
			body:     `{"foo":"bar"}`,
			wantBody: `{"foo":"bar"}`,
		},
		{
			name:     "204 No Content passes through",
			status:   204,
			body:     ``,
			wantBody: ``,
		},
		{
			name:     "malformed JSON passes through",
			status:   200,
			body:     `{not valid}`,
			wantBody: `{not valid}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := echo.New()
			e.Use(SingletonEnvelopeWrapper())
			e.GET("/test", func(ctx echo.Context) error {
				if c.body != "" {
					ctx.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
				}
				return ctx.Blob(c.status, echo.MIMEApplicationJSON, []byte(c.body))
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			got := strings.TrimSpace(rec.Body.String())
			want := strings.TrimSpace(c.wantBody)
			if got != want {
				t.Errorf("body mismatch:\n  got:  %s\n  want: %s", got, want)
			}
			if rec.Code != c.status && c.status != 204 {
				t.Errorf("status mismatch: got=%d want=%d", rec.Code, c.status)
			}
		})
	}
}

// TestSingletonEnvelopeWrapper_NonJSONPassthrough — non-JSON Content-Type
// (e.g. text/event-stream for SSE, application/octet-stream for binary
// audio) MUST pass through untouched. Otherwise the wrapper would corrupt
// streaming bodies.
func TestSingletonEnvelopeWrapper_NonJSONPassthrough(t *testing.T) {
	e := echo.New()
	e.Use(SingletonEnvelopeWrapper())
	e.GET("/sse", func(ctx echo.Context) error {
		return ctx.Blob(200, "text/event-stream", []byte("event: ping\ndata: {}\n\n"))
	})

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Body.String() != "event: ping\ndata: {}\n\n" {
		t.Errorf("non-JSON body was modified: %q", rec.Body.String())
	}
}

func TestSingletonEnvelopeWrapper_PanicReachesRecoverAs500(t *testing.T) {
	for name, handler := range map[string]echo.HandlerFunc{
		"before writing": func(c echo.Context) error { panic("boom") },
		"after writing": func(c echo.Context) error {
			_ = c.JSON(http.StatusOK, map[string]string{"id": "x"})
			panic("boom")
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := echo.New()
			e.Use(echomw.Recover())
			e.Use(SingletonEnvelopeWrapper())
			e.GET("/x", handler)
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
			if rec.Body.Len() == 0 {
				t.Fatal("empty body: the error envelope never reached the client")
			}
		})
	}
}
