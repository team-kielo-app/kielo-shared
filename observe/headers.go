package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	// HeaderTraceparent is the W3C standard trace propagation header.
	HeaderTraceparent = "Traceparent"
	// HeaderRequestID is a human-friendly request correlation header.
	HeaderRequestID = "X-Request-Id"
	// HeaderClientTraceID is the mobile-app trace header (backward compat).
	HeaderClientTraceID = "X-Client-Trace-Id"
)

var (
	traceparentRe = regexp.MustCompile(`^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
	hexOnly32     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	zeroTraceID   = strings.Repeat("0", 32)
	zeroSpanID    = strings.Repeat("0", 16)
)

// Traceparent formats the TraceContext as a W3C traceparent header value.
// Format: "00-{trace_id}-{span_id}-{flags}"
func (tc TraceContext) Traceparent() string {
	return fmt.Sprintf("00-%s-%s-%02x", tc.TraceID, tc.SpanID, tc.Flags)
}

// ParseTraceparent parses a W3C traceparent header value into a TraceContext.
// Rejects invalid format, version ff, all-zero trace-id, and all-zero parent-id
// per the W3C Trace Context specification.
func ParseTraceparent(s string) (TraceContext, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	matches := traceparentRe.FindStringSubmatch(s)
	if matches == nil {
		return TraceContext{}, fmt.Errorf("observe: invalid traceparent format: %q", s)
	}

	version := matches[1]
	if version == "ff" {
		return TraceContext{}, fmt.Errorf("observe: version ff is invalid")
	}

	traceID := matches[2]
	if traceID == zeroTraceID {
		return TraceContext{}, fmt.Errorf("observe: all-zero trace-id is invalid")
	}

	spanID := matches[3]
	if spanID == zeroSpanID {
		return TraceContext{}, fmt.Errorf("observe: all-zero parent-id (span-id) is invalid")
	}

	flags, _ := hex.DecodeString(matches[4])

	return TraceContext{
		TraceID: traceID,
		SpanID:  spanID,
		Flags:   flags[0],
	}, nil
}

// FromHeaders extracts a TraceContext from HTTP headers using the precedence:
//  1. traceparent header (W3C standard)
//  2. X-Client-Trace-Id header (mobile app backward compat)
//  3. Generate fresh IDs
//
// X-Request-Id is always read independently if present.
func FromHeaders(h http.Header) TraceContext {
	var tc TraceContext

	// Try W3C traceparent first
	if tp := h.Get(HeaderTraceparent); tp != "" {
		if parsed, err := ParseTraceparent(tp); err == nil {
			tc = parsed
		}
	}

	// Fallback: X-Client-Trace-Id
	if tc.TraceID == "" {
		if clientTrace := h.Get(HeaderClientTraceID); clientTrace != "" {
			tc.TraceID = normalizeToTraceID(clientTrace)
			tc.SpanID = randomHex(8)
			tc.Flags = 0x01
		}
	}

	// Fallback: generate fresh
	if tc.TraceID == "" {
		tc = New()
	}

	// X-Request-Id: use from header if present, otherwise keep generated
	if reqID := h.Get(HeaderRequestID); reqID != "" {
		tc.RequestID = reqID
	} else if tc.RequestID == "" {
		tc.RequestID = generateRequestID()
	}

	return tc
}

// InjectHeaders writes trace headers into an http.Header.
// Sets traceparent, X-Request-Id, and X-Client-Trace-Id (backward compat).
func InjectHeaders(h http.Header, tc TraceContext) {
	if tc.IsZero() {
		return
	}
	h.Set(HeaderTraceparent, tc.Traceparent())
	if tc.RequestID != "" {
		h.Set(HeaderRequestID, tc.RequestID)
	}
	// Backward compat: also set X-Client-Trace-Id so downstream services
	// that haven't adopted traceparent yet can still correlate.
	h.Set(HeaderClientTraceID, tc.TraceID)
}

// normalizeToTraceID converts an arbitrary string to a 32 hex char trace ID.
// If the string is already a valid 32-char hex string, it's returned as-is.
// Otherwise, it's SHA-256 hashed and truncated to 32 hex chars.
func normalizeToTraceID(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	if hexOnly32.MatchString(lower) {
		return lower
	}
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:16]) // first 16 bytes = 32 hex chars
}
