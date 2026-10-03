package observe

import (
	"context"
	"strings"
	"testing"
)

func TestStoredTraceID_NoTraceIsNil(t *testing.T) {
	if got := StoredTraceID(context.Background()); got != nil {
		t.Fatalf("StoredTraceID without trace = %q, want nil", *got)
	}
}

func TestStoredTraceID_RoundTripsThroughWithStoredTrace(t *testing.T) {
	writer := New()
	stored := StoredTraceID(WithContext(context.Background(), writer))
	if stored == nil || *stored != writer.TraceID {
		t.Fatalf("StoredTraceID = %v, want %q", stored, writer.TraceID)
	}

	drainCycle := New()
	restored, ok := FromContext(WithStoredTrace(WithContext(context.Background(), drainCycle), stored))
	if !ok {
		t.Fatal("WithStoredTrace dropped the trace context")
	}
	if restored.TraceID != writer.TraceID {
		t.Errorf("restored TraceID = %q, want writer's %q", restored.TraceID, writer.TraceID)
	}
	if restored.SpanID == writer.SpanID || restored.SpanID == drainCycle.SpanID {
		t.Error("restored context must carry a fresh span")
	}
}

func TestWithStoredTrace_InvalidKeepsCycleTrace(t *testing.T) {
	cycle := New()
	ctx := WithContext(context.Background(), cycle)
	for name, v := range map[string]*string{
		"nil":        nil,
		"empty":      ptr(""),
		"short":      ptr("abc"),
		"uppercase":  ptr(strings.ToUpper(New().TraceID)),
		"all zeroes": ptr(strings.Repeat("0", 32)),
		"non-hex":    ptr(strings.Repeat("g", 32)),
	} {
		got, _ := FromContext(WithStoredTrace(ctx, v))
		if got.TraceID != cycle.TraceID {
			t.Errorf("%s: TraceID = %q, want cycle trace %q", name, got.TraceID, cycle.TraceID)
		}
	}
}

func ptr(s string) *string { return &s }
