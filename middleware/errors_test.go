package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
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
