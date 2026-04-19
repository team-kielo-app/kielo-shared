// Package pubsubutil provides helpers for propagating trace context through
// Google Cloud Pub/Sub message attributes.
//
// Usage (publisher):
//
//	attrs := map[string]string{"event_type": "content.published.v1"}
//	pubsubutil.InjectTraceAttributes(attrs, ctx)
//	topic.Publish(ctx, &pubsub.Message{Data: data, Attributes: attrs})
//
// Usage (subscriber):
//
//	ctx = pubsubutil.ConsumerContext(ctx, msg.Attributes)
package pubsubutil

import (
	"github.com/team-kielo-app/kielo-shared/observe"
	"context"
)

const (
	attrTraceID   = "trace_id"
	attrSpanID    = "span_id"
	attrRequestID = "request_id"
)

// InjectTraceAttributes adds trace_id, span_id, and request_id from the
// context's [observe.TraceContext] into a Pub/Sub message attributes map.
// Existing attributes (like event_type) are preserved.
// No-op if context has no TraceContext.
func InjectTraceAttributes(attrs map[string]string, ctx context.Context) {
	tc, ok := observe.FromContext(ctx)
	if !ok || tc.IsZero() {
		return
	}
	attrs[attrTraceID] = tc.TraceID
	attrs[attrSpanID] = tc.SpanID
	if tc.RequestID != "" {
		attrs[attrRequestID] = tc.RequestID
	}
}

// ExtractTraceContext reconstructs a [observe.TraceContext] from Pub/Sub message
// attributes. Returns false if trace_id is not present in the attributes.
//
// Note: the returned TraceContext carries the publisher's span_id. Use
// [ConsumerContext] instead to automatically create a child span for the
// subscriber, avoiding accidental reuse of the producer's span.
func ExtractTraceContext(attrs map[string]string) (observe.TraceContext, bool) {
	traceID := attrs[attrTraceID]
	if traceID == "" {
		return observe.TraceContext{}, false
	}
	return observe.TraceContext{
		TraceID:   traceID,
		SpanID:    attrs[attrSpanID],
		RequestID: attrs[attrRequestID],
		Flags:     0x01,
	}, true
}

// ConsumerContext extracts trace context from Pub/Sub message attributes and
// creates a child span for the subscriber. This is the recommended way to start
// processing a received message — the subscriber gets its own span_id while
// preserving the publisher's trace_id and request_id.
//
// If no trace attributes are present, the context is returned unchanged.
func ConsumerContext(ctx context.Context, attrs map[string]string) context.Context {
	producer, ok := ExtractTraceContext(attrs)
	if !ok {
		return ctx
	}
	consumer := observe.ChildSpan(producer)
	return observe.WithContext(ctx, consumer)
}
