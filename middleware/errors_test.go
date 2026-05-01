package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestLogInternalError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	underlying := errors.New("pq: relation 'foo' does not exist")
	got := LogInternalError(c, underlying, "GetFoo failed for id=%s", "abc")

	if got.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want %d", got.Code, http.StatusInternalServerError)
	}
	// Crucially, the public message is opaque — it must NOT contain the
	// underlying error string, the table name, or any other internal detail.
	msg, ok := got.Message.(string)
	if !ok {
		t.Fatalf("Message is %T, expected string", got.Message)
	}
	if msg == "" {
		t.Errorf("Message should not be empty")
	}
	bannedSubstrings := []string{"pq:", "relation", "foo", "abc", "GetFoo"}
	for _, banned := range bannedSubstrings {
		if contains(msg, banned) {
			t.Errorf("Message %q must not leak internal detail %q", msg, banned)
		}
	}
}

func TestLogInternalError_NilErr(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	got := LogInternalError(c, nil, "operator-only log line")
	if got.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", got.Code)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestAPIError_DefaultCodeAndEnvelope(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := APIError(c, http.StatusNotFound, "", "session not found", nil); err != nil {
		t.Fatalf("APIError returned err: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != "NOT_FOUND" {
		t.Errorf("code = %q, want NOT_FOUND", env.Error.Code)
	}
	if env.Error.Message != "session not found" {
		t.Errorf("error.message = %q", env.Error.Message)
	}
	if env.Message != "session not found" {
		t.Errorf("legacy message = %q (must mirror error.message)", env.Message)
	}
}

func TestAPIError_ExplicitCodeAndDetails(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	details := map[string]any{"field": "session_id"}
	_ = APIError(c, http.StatusBadRequest, "INVALID_REQUEST", "bad", details)

	var env ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != "INVALID_REQUEST" {
		t.Errorf("code = %q", env.Error.Code)
	}
	if env.Error.Details["field"] != "session_id" {
		t.Errorf("details = %v", env.Error.Details)
	}
}

func TestAPIError_PropagatesTraceID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	tc := observe.New()
	req = req.WithContext(observe.WithContext(req.Context(), tc))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_ = APIError(c, http.StatusInternalServerError, "", "boom", nil)

	var env ErrorEnvelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.Error.TraceID != tc.TraceID {
		t.Errorf("trace_id = %q, want %q", env.Error.TraceID, tc.TraceID)
	}
	if env.Error.Code != "INTERNAL_ERROR" {
		t.Errorf("code = %q", env.Error.Code)
	}
}

func TestAPIErrorStdlib_WritesEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	APIErrorStdlib(rec, context.Background(), http.StatusConflict, "SESSION_ENDED", "ended", nil)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", got)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != "SESSION_ENDED" || env.Error.Message != "ended" || env.Message != "ended" {
		t.Errorf("envelope = %+v", env)
	}
}

func TestCanonicalEchoErrorHandler_WrapsHTTPError(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = CanonicalEchoErrorHandler
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	CanonicalEchoErrorHandler(echo.NewHTTPError(http.StatusBadRequest, "bad input"), c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rec.Code)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != "BAD_REQUEST" || env.Error.Message != "bad input" {
		t.Errorf("envelope = %+v", env)
	}
}

func TestDefaultCodeForStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, "BAD_REQUEST"},
		{http.StatusUnauthorized, "UNAUTHORIZED"},
		{http.StatusForbidden, "FORBIDDEN"},
		{http.StatusNotFound, "NOT_FOUND"},
		{http.StatusConflict, "CONFLICT"},
		{http.StatusUnprocessableEntity, "VALIDATION_FAILED"},
		{http.StatusTooManyRequests, "RATE_LIMITED"},
		{http.StatusInternalServerError, "INTERNAL_ERROR"},
		{http.StatusBadGateway, "INTERNAL_ERROR"},
		{http.StatusServiceUnavailable, "INTERNAL_ERROR"},
		{http.StatusTeapot, "ERROR"},
	}
	for _, tc := range cases {
		if got := defaultCodeForStatus(tc.status); got != tc.want {
			t.Errorf("defaultCodeForStatus(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}
