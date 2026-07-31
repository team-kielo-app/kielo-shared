package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func denyResponse(
	t *testing.T, message string, retryAfter time.Duration,
) (rec *httptest.ResponseRecorder, body map[string]any) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/whatever", nil)
	rec = httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := WriteRateLimitDenied(c, message, retryAfter); err != nil {
		t.Fatalf("WriteRateLimitDenied: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec, body
}

func errorObject(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, ok := body["error"]
	if !ok {
		t.Fatalf("no `error` key: %v", body)
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("`error` is %T, not an object — the client only reads error.code off an object", raw)
	}
	return obj
}

func TestRateLimitDeniedIsClassifiable(t *testing.T) {
	rec, body := denyResponse(t, "Too many feedback submissions. Please try again later.", time.Minute)
	errObj := errorObject(t, body)

	if errObj["code"] != "RATE_LIMITED" {
		t.Errorf("error.code = %v, want RATE_LIMITED", errObj["code"])
	}
	if errObj["code"] == "FEATURE_LIMIT_REACHED" {
		t.Error("a transient rate limit must not claim the quota code — it would offer an upgrade that fixes nothing")
	}
	if got := body["message"]; got != "Too many feedback submissions. Please try again later." {
		t.Errorf("top-level message = %v, want the caller's copy (the client shows it verbatim)", got)
	}
	if got := errObj["retry_after_seconds"]; got != float64(60) {
		t.Errorf("retry_after_seconds = %v, want 60", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After header = %q, want 60", got)
	}
}

func TestRateLimitDeniedFallsBackToDefaultCopy(t *testing.T) {
	_, body := denyResponse(t, "", time.Minute)
	if body["message"] == "" || body["message"] == nil {
		t.Error("empty caller copy must fall back to a usable sentence, not an empty alert")
	}
	if errorObject(t, body)["message"] != body["message"] {
		t.Error("error.message should mirror the top-level message so either read shows the same thing")
	}
}

// A limiter with an unknown or unset window must not advertise "retry now".
func TestRateLimitDeniedOmitsRetryWhenUnknown(t *testing.T) {
	for _, window := range []time.Duration{0, -5 * time.Second} {
		rec, body := denyResponse(t, "slow down", window)
		errObj := errorObject(t, body)
		if _, present := errObj["retry_after_seconds"]; present {
			t.Errorf("window %v: retry_after_seconds must be omitted, not 0 — 0 invites an immediate retry loop", window)
		}
		if got := rec.Header().Get("Retry-After"); got != "" {
			t.Errorf("window %v: Retry-After header = %q, want absent", window, got)
		}
		if errObj["code"] != "RATE_LIMITED" {
			t.Errorf("window %v: code must still be present so the client can classify", window)
		}
	}
}

// Sub-second windows still deserve a truthful wait rather than being rounded away
// to "retry immediately".
func TestRateLimitDeniedRoundsSubSecondWindowsUp(t *testing.T) {
	rec, body := denyResponse(t, "slow down", 200*time.Millisecond)
	if got := errorObject(t, body)["retry_after_seconds"]; got != float64(1) {
		t.Errorf("retry_after_seconds = %v, want 1 for a sub-second window", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
}

// Retry-After is an integer number of seconds per RFC 9110 §10.2.3 — never a
// float, which some clients reject outright.
func TestRateLimitDeniedRetryAfterIsAnInteger(t *testing.T) {
	rec, _ := denyResponse(t, "slow down", 90*time.Second+400*time.Millisecond)
	got := rec.Header().Get("Retry-After")
	if got != "90" {
		t.Errorf("Retry-After = %q, want 90 (integer seconds, rounded)", got)
	}
	for _, ch := range got {
		if ch < '0' || ch > '9' {
			t.Fatalf("Retry-After %q contains a non-digit", got)
		}
	}
}

// The body must be exactly one JSON document: a second write would make the
// client's JSON.parse throw and it would fall back to treating the body as text.
func TestRateLimitDeniedWritesExactlyOneDocument(t *testing.T) {
	rec, _ := denyResponse(t, "slow down", time.Minute)
	dec := json.NewDecoder(rec.Body)
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("first document did not decode: %v", err)
	}
	var second json.RawMessage
	if err := dec.Decode(&second); err == nil {
		t.Fatalf("body carries more than one JSON document: %s", rec.Body.String())
	}
}
