package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestNew_IncludesServiceField(t *testing.T) {
	var buf bytes.Buffer
	logger := New("kielo-cms", WithOutput(&buf))

	logger.Info("hello")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if entry["service"] != "kielo-cms" {
		t.Errorf("service = %v, want kielo-cms", entry["service"])
	}
	if entry["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", entry["msg"])
	}
}

func TestNew_RespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test", WithLevel(slog.LevelWarn), WithOutput(&buf))

	logger.Info("should not appear")
	if buf.Len() > 0 {
		t.Errorf("info message should be suppressed at warn level: %s", buf.String())
	}

	logger.Warn("should appear")
	if buf.Len() == 0 {
		t.Error("warn message should appear at warn level")
	}
}

func TestNew_LOGLEVELEnv(t *testing.T) {
	t.Setenv("LOG_LEVEL", "ERROR")

	var buf bytes.Buffer
	logger := New("test", WithOutput(&buf))

	logger.Warn("should not appear")
	if buf.Len() > 0 {
		t.Errorf("warn should be suppressed at error level: %s", buf.String())
	}
}

func TestHandler_InjectsTraceFields(t *testing.T) {
	var buf bytes.Buffer
	handler := Handler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(handler)

	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	logger.InfoContext(ctx, "traced log")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}
	if entry["trace_id"] != tc.TraceID {
		t.Errorf("trace_id = %v, want %s", entry["trace_id"], tc.TraceID)
	}
	if entry["span_id"] != tc.SpanID {
		t.Errorf("span_id = %v, want %s", entry["span_id"], tc.SpanID)
	}
	if entry["request_id"] != tc.RequestID {
		t.Errorf("request_id = %v, want %s", entry["request_id"], tc.RequestID)
	}
}

func TestHandler_NoTraceContext(t *testing.T) {
	var buf bytes.Buffer
	handler := Handler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(handler)

	logger.InfoContext(context.Background(), "no trace")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, exists := entry["trace_id"]; exists {
		t.Error("trace_id should not be present without TraceContext")
	}
}

func TestFromContext_Fallback(t *testing.T) {
	logger := FromContext(context.Background())
	if logger == nil {
		t.Fatal("FromContext should return a non-nil logger even without stored logger")
	}
}

func TestWithContext_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test-svc", WithOutput(&buf))

	ctx := WithContext(context.Background(), logger)
	got := FromContext(ctx)

	got.Info("from context")
	if buf.Len() == 0 {
		t.Error("logger from context should write to the same buffer")
	}
}

func TestHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	handler := Handler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(handler).With("extra", "value")

	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)
	logger.InfoContext(ctx, "test")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["extra"] != "value" {
		t.Errorf("extra = %v, want 'value'", entry["extra"])
	}
	if entry["trace_id"] != tc.TraceID {
		t.Errorf("trace_id missing after WithAttrs")
	}
}
