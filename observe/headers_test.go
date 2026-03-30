package observe

import (
	"net/http"
	"testing"
)

func TestParseTraceparent_Valid(t *testing.T) {
	tc, err := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("TraceID = %q", tc.TraceID)
	}
	if tc.SpanID != "00f067aa0ba902b7" {
		t.Errorf("SpanID = %q", tc.SpanID)
	}
	if tc.Flags != 0x01 {
		t.Errorf("Flags = %02x, want 01", tc.Flags)
	}
}

func TestParseTraceparent_CaseInsensitive(t *testing.T) {
	_, err := ParseTraceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01")
	if err != nil {
		t.Errorf("should accept uppercase: %v", err)
	}
}

func TestParseTraceparent_AllZeroTraceID(t *testing.T) {
	_, err := ParseTraceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
	if err == nil {
		t.Error("should reject all-zero trace-id")
	}
}

func TestParseTraceparent_AllZeroSpanID(t *testing.T) {
	_, err := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01")
	if err == nil {
		t.Error("should reject all-zero parent-id (span-id)")
	}
}

func TestParseTraceparent_VersionFF(t *testing.T) {
	_, err := ParseTraceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err == nil {
		t.Error("should reject version ff")
	}
}

func TestParseTraceparent_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"invalid",
		"00-short-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-short-01",
		"xx-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}
	for _, c := range cases {
		if _, err := ParseTraceparent(c); err == nil {
			t.Errorf("ParseTraceparent(%q) should have returned error", c)
		}
	}
}

func TestTraceparentRoundTrip(t *testing.T) {
	tc := New()
	s := tc.Traceparent()

	parsed, err := ParseTraceparent(s)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if parsed.TraceID != tc.TraceID {
		t.Errorf("TraceID mismatch: %q vs %q", parsed.TraceID, tc.TraceID)
	}
	if parsed.SpanID != tc.SpanID {
		t.Errorf("SpanID mismatch: %q vs %q", parsed.SpanID, tc.SpanID)
	}
	if parsed.Flags != tc.Flags {
		t.Errorf("Flags mismatch: %02x vs %02x", parsed.Flags, tc.Flags)
	}
}

func TestFromHeaders_Traceparent(t *testing.T) {
	h := http.Header{}
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("X-Request-Id", "my-request-123")

	tc := FromHeaders(h)
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("TraceID = %q", tc.TraceID)
	}
	if tc.RequestID != "my-request-123" {
		t.Errorf("RequestID = %q, want 'my-request-123'", tc.RequestID)
	}
}

func TestFromHeaders_ClientTraceIdFallback(t *testing.T) {
	h := http.Header{}
	h.Set("X-Client-Trace-Id", "trace-e2e-word-cluster")

	tc := FromHeaders(h)
	if tc.TraceID == "" {
		t.Fatal("TraceID should not be empty")
	}
	if len(tc.TraceID) != 32 {
		t.Errorf("TraceID length = %d, want 32 (normalized)", len(tc.TraceID))
	}
	if tc.SpanID == "" {
		t.Error("SpanID should be generated")
	}
}

func TestFromHeaders_ClientTraceId_AlreadyHex32(t *testing.T) {
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	h := http.Header{}
	h.Set("X-Client-Trace-Id", traceID)

	tc := FromHeaders(h)
	if tc.TraceID != traceID {
		t.Errorf("TraceID = %q, want %q (should use as-is)", tc.TraceID, traceID)
	}
}

func TestFromHeaders_GeneratesNew(t *testing.T) {
	h := http.Header{}
	tc := FromHeaders(h)
	if tc.TraceID == "" {
		t.Error("should generate fresh TraceID")
	}
	if tc.RequestID == "" {
		t.Error("should generate fresh RequestID")
	}
}

func TestFromHeaders_PreservesRequestId(t *testing.T) {
	h := http.Header{}
	h.Set("X-Request-Id", "custom-req-id")

	tc := FromHeaders(h)
	if tc.RequestID != "custom-req-id" {
		t.Errorf("RequestID = %q, want 'custom-req-id'", tc.RequestID)
	}
}

func TestInjectHeaders(t *testing.T) {
	tc := TraceContext{
		TraceID:   "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:    "00f067aa0ba902b7",
		RequestID: "20260330T134512-a3f2",
		Flags:     0x01,
	}

	h := http.Header{}
	InjectHeaders(h, tc)

	if got := h.Get("Traceparent"); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Errorf("Traceparent = %q", got)
	}
	if got := h.Get("X-Request-Id"); got != "20260330T134512-a3f2" {
		t.Errorf("X-Request-Id = %q", got)
	}
	if got := h.Get("X-Client-Trace-Id"); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("X-Client-Trace-Id = %q", got)
	}
}

func TestInjectHeaders_Zero(t *testing.T) {
	h := http.Header{}
	InjectHeaders(h, TraceContext{})
	if h.Get("Traceparent") != "" {
		t.Error("should not inject headers for zero TraceContext")
	}
}

func TestNormalizeToTraceID_Deterministic(t *testing.T) {
	a := normalizeToTraceID("trace-e2e-word-cluster")
	b := normalizeToTraceID("trace-e2e-word-cluster")
	if a != b {
		t.Errorf("normalizeToTraceID not deterministic: %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Errorf("length = %d, want 32", len(a))
	}
}
