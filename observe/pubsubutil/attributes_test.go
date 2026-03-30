package pubsubutil

import (
	"context"
	"testing"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestInjectAndExtract_RoundTrip(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	attrs := map[string]string{"event_type": "test.event.v1"}
	InjectTraceAttributes(attrs, ctx)

	// event_type should be preserved
	if attrs["event_type"] != "test.event.v1" {
		t.Errorf("event_type = %q, was overwritten", attrs["event_type"])
	}

	extracted, ok := ExtractTraceContext(attrs)
	if !ok {
		t.Fatal("ExtractTraceContext returned false")
	}
	if extracted.TraceID != tc.TraceID {
		t.Errorf("TraceID = %q, want %q", extracted.TraceID, tc.TraceID)
	}
	if extracted.SpanID != tc.SpanID {
		t.Errorf("SpanID = %q, want %q", extracted.SpanID, tc.SpanID)
	}
	if extracted.RequestID != tc.RequestID {
		t.Errorf("RequestID = %q, want %q", extracted.RequestID, tc.RequestID)
	}
}

func TestInject_NoTraceContext(t *testing.T) {
	attrs := map[string]string{"event_type": "test.event.v1"}
	InjectTraceAttributes(attrs, context.Background())

	if _, exists := attrs["trace_id"]; exists {
		t.Error("should not inject trace_id without TraceContext in context")
	}
	if attrs["event_type"] != "test.event.v1" {
		t.Error("existing attributes should be preserved")
	}
}

func TestExtract_MissingAttributes(t *testing.T) {
	attrs := map[string]string{"event_type": "test.event.v1"}
	_, ok := ExtractTraceContext(attrs)
	if ok {
		t.Error("should return false when trace_id not in attributes")
	}
}

func TestExtract_PartialAttributes(t *testing.T) {
	attrs := map[string]string{
		"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
		// span_id and request_id missing
	}
	tc, ok := ExtractTraceContext(attrs)
	if !ok {
		t.Fatal("should return true when trace_id is present")
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("TraceID = %q", tc.TraceID)
	}
	if tc.SpanID != "" {
		t.Errorf("SpanID = %q, want empty for partial attributes", tc.SpanID)
	}
}

func TestConsumerContext_CreatesChildSpan(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	attrs := map[string]string{}
	InjectTraceAttributes(attrs, ctx)

	// Simulate subscriber receiving the message
	consumerCtx := ConsumerContext(context.Background(), attrs)
	consumer, ok := observe.FromContext(consumerCtx)
	if !ok {
		t.Fatal("ConsumerContext should store TraceContext")
	}
	if consumer.TraceID != tc.TraceID {
		t.Errorf("consumer TraceID = %q, want producer's %q", consumer.TraceID, tc.TraceID)
	}
	if consumer.SpanID == tc.SpanID {
		t.Error("consumer SpanID should differ from producer's (child span)")
	}
	if consumer.ParentSpanID != tc.SpanID {
		t.Errorf("consumer ParentSpanID = %q, want producer's SpanID %q", consumer.ParentSpanID, tc.SpanID)
	}
	if consumer.RequestID != tc.RequestID {
		t.Errorf("consumer RequestID = %q, want producer's %q", consumer.RequestID, tc.RequestID)
	}
}

func TestConsumerContext_NoAttributes(t *testing.T) {
	ctx := context.Background()
	result := ConsumerContext(ctx, map[string]string{"event_type": "test"})
	if _, ok := observe.FromContext(result); ok {
		t.Error("should not inject TraceContext when no trace attributes present")
	}
}

func TestInject_PreservesExistingAttributes(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	attrs := map[string]string{
		"event_type": "content.published.v1",
		"source":     "kielo-cms",
		"version":    "2",
	}
	InjectTraceAttributes(attrs, ctx)

	if attrs["event_type"] != "content.published.v1" {
		t.Error("event_type was modified")
	}
	if attrs["source"] != "kielo-cms" {
		t.Error("source was modified")
	}
	if attrs["version"] != "2" {
		t.Error("version was modified")
	}
	if attrs["trace_id"] != tc.TraceID {
		t.Error("trace_id not injected")
	}
}
