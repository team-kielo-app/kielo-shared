// Package observe provides distributed tracing primitives based on the W3C
// traceparent standard. It defines a lightweight TraceContext that flows through
// stdlib context.Context, enabling correlation of logs and requests across
// services without requiring a full OpenTelemetry SDK.
package observe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// TraceContext carries trace correlation IDs through request processing.
type TraceContext struct {
	TraceID      string // 32 hex chars (16 bytes), W3C trace-id
	SpanID       string // 16 hex chars (8 bytes), W3C span-id (this hop)
	ParentSpanID string // 16 hex chars, empty if root span
	RequestID    string // Human-friendly ID: "20060102T150405-a3f2"
	Flags        byte   // W3C trace-flags, default 0x01 (sampled)
}

type contextKey struct{}

// New creates a fresh TraceContext with random IDs.
func New() TraceContext {
	return TraceContext{
		TraceID:   randomHex(16),
		SpanID:    randomHex(8),
		RequestID: generateRequestID(),
		Flags:     0x01,
	}
}

// ChildSpan creates a new span that inherits the parent's TraceID and RequestID
// but has a fresh SpanID and records the parent's SpanID.
func ChildSpan(parent TraceContext) TraceContext {
	return TraceContext{
		TraceID:      parent.TraceID,
		SpanID:       randomHex(8),
		ParentSpanID: parent.SpanID,
		RequestID:    parent.RequestID,
		Flags:        parent.Flags,
	}
}

// WithContext stores a TraceContext in a context.Context.
func WithContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, contextKey{}, tc)
}

// FromContext retrieves a TraceContext from a context.Context.
// Returns the zero value and false if not present.
func FromContext(ctx context.Context) (TraceContext, bool) {
	tc, ok := ctx.Value(contextKey{}).(TraceContext)
	return tc, ok
}

// IsZero returns true if the TraceContext has no TraceID set.
func (tc TraceContext) IsZero() bool {
	return tc.TraceID == ""
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("observe: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func generateRequestID() string {
	ts := time.Now().UTC().Format("20060102T150405")
	suffix := randomHex(2) // 4 hex chars
	return ts + "-" + suffix
}
