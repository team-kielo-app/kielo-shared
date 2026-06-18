package sse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewStdlibWriter_SetsCanonicalHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := NewStdlibWriter(rec)
	if err != nil {
		t.Fatalf("NewStdlibWriter: %v", err)
	}
	_ = w

	got := rec.Header()
	if got.Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q", got.Get("Cache-Control"))
	}
	if got.Get("Connection") != "keep-alive" {
		t.Errorf("Connection = %q", got.Get("Connection"))
	}
	if got.Get("X-Accel-Buffering") != "no" {
		t.Errorf("X-Accel-Buffering = %q (proxy buffering will break long streams)", got.Get("X-Accel-Buffering"))
	}
}

func TestNewStdlibWriter_NoFlusher(t *testing.T) {
	// Wrap the recorder in a type that does NOT implement http.Flusher.
	w := nonFlushingWriter{ResponseWriter: httptest.NewRecorder()}
	_, err := NewStdlibWriter(w)
	if err == nil {
		t.Fatal("expected error when response writer is not a Flusher")
	}
}

type nonFlushingWriter struct {
	http.ResponseWriter
}

func TestStdlibWriter_SendEvent_FrameShape(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := NewStdlibWriter(rec)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.SendEvent("job_status", map[string]any{"job_id": "abc", "status": "running"}); err != nil {
		t.Fatal(err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: job_status\n") {
		t.Errorf("missing event line: %q", body)
	}
	if !strings.Contains(body, `data: {"job_id":"abc","status":"running"}`+"\n\n") {
		t.Errorf("malformed data frame: %q", body)
	}
}

func TestStdlibWriter_SendComment_FrameShape(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := NewStdlibWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SendComment("heartbeat"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), ": heartbeat\n\n") {
		t.Errorf("comment frame missing: %q", rec.Body.String())
	}
}

func TestStdlibWriter_SendRetry(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := NewStdlibWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SendRetry(5000); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), "retry: 5000\n\n") {
		t.Errorf("retry frame missing: %q", rec.Body.String())
	}
}

func TestStdlibWriter_Heartbeat(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := NewStdlibWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	w.SetHeartbeatDelay(10 * time.Millisecond)
	w.StartHeartbeat()
	time.Sleep(35 * time.Millisecond)
	w.StopHeartbeat()
	// Should have emitted at least 2 heartbeat comments (plus the
	// initial "connected" comment from NewStdlibWriter).
	if strings.Count(rec.Body.String(), ": heartbeat\n\n") < 2 {
		t.Errorf("expected at least 2 heartbeats; body: %q", rec.Body.String())
	}
}

func TestStdlibWriter_StopHeartbeat_Idempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	w, _ := NewStdlibWriter(rec)
	w.StartHeartbeat()
	w.StopHeartbeat()
	w.StopHeartbeat() // must not panic
}
