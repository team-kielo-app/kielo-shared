package observe

import (
	"context"
	"regexp"
	"testing"
)

func TestNew(t *testing.T) {
	tc := New()

	if len(tc.TraceID) != 32 {
		t.Errorf("TraceID length = %d, want 32", len(tc.TraceID))
	}
	if len(tc.SpanID) != 16 {
		t.Errorf("SpanID length = %d, want 16", len(tc.SpanID))
	}
	if tc.ParentSpanID != "" {
		t.Errorf("ParentSpanID = %q, want empty for root span", tc.ParentSpanID)
	}
	if tc.Flags != 0x01 {
		t.Errorf("Flags = %02x, want 01", tc.Flags)
	}

	// RequestID should match timestamp-hex pattern
	re := regexp.MustCompile(`^\d{8}T\d{6}-[0-9a-f]{4}$`)
	if !re.MatchString(tc.RequestID) {
		t.Errorf("RequestID = %q, does not match expected pattern", tc.RequestID)
	}
}

func TestNew_Uniqueness(t *testing.T) {
	a := New()
	b := New()
	if a.TraceID == b.TraceID {
		t.Error("two New() calls produced the same TraceID")
	}
	if a.SpanID == b.SpanID {
		t.Error("two New() calls produced the same SpanID")
	}
}

func TestChildSpan(t *testing.T) {
	parent := New()
	child := ChildSpan(parent)

	if child.TraceID != parent.TraceID {
		t.Errorf("child TraceID = %q, want parent's %q", child.TraceID, parent.TraceID)
	}
	if child.RequestID != parent.RequestID {
		t.Errorf("child RequestID = %q, want parent's %q", child.RequestID, parent.RequestID)
	}
	if child.SpanID == parent.SpanID {
		t.Error("child SpanID should differ from parent")
	}
	if child.ParentSpanID != parent.SpanID {
		t.Errorf("child ParentSpanID = %q, want parent SpanID %q", child.ParentSpanID, parent.SpanID)
	}
	if child.Flags != parent.Flags {
		t.Errorf("child Flags = %02x, want parent's %02x", child.Flags, parent.Flags)
	}
}

func TestContextRoundTrip(t *testing.T) {
	tc := New()
	ctx := WithContext(context.Background(), tc)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext returned false")
	}
	if got.TraceID != tc.TraceID {
		t.Errorf("TraceID = %q, want %q", got.TraceID, tc.TraceID)
	}
	if got.SpanID != tc.SpanID {
		t.Errorf("SpanID = %q, want %q", got.SpanID, tc.SpanID)
	}
	if got.RequestID != tc.RequestID {
		t.Errorf("RequestID = %q, want %q", got.RequestID, tc.RequestID)
	}
}

func TestFromContext_Missing(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext on empty context should return false")
	}
}

func TestIsZero(t *testing.T) {
	var tc TraceContext
	if !tc.IsZero() {
		t.Error("zero TraceContext should return IsZero=true")
	}
	tc = New()
	if tc.IsZero() {
		t.Error("New() TraceContext should not be zero")
	}
}
