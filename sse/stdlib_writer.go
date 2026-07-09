// stdlib_writer.go: SSE writer for chi/raw net/http handlers.
//
// The pre-existing Writer (writer.go) targets Echo handlers via
// echo.Context. Services that don't run on Echo — currently
// kielo-convo's chi router and any future raw-net/http callers — used
// to hand-roll the canonical SSE header set:
//
//   w.Header().Set("Content-Type", "text/event-stream")
//   w.Header().Set("Cache-Control", "no-cache")
//   w.Header().Set("Connection", "keep-alive")
//   w.Header().Set("X-Accel-Buffering", "no")
//
// The hand-rolled form drifts: kielo-convo has two SSE endpoints with
// slightly different headers (one sets Connection: keep-alive, the
// other omits it; one sets X-Accel-Buffering, the other forgets to,
// which surfaces as 30 s nginx buffering in front of long-running
// streams).
//
// NewStdlibWriter centralizes the header set + flush discipline +
// heartbeat plumbing so non-Echo services get the same wire behavior
// as Echo handlers. Per ADR-006 §7.
//
// Wire shape:
//   - frame:    "event: <name>\n" (when name set) + "data: <json>\n\n"
//   - comment:  ": <text>\n\n"
//   - heartbeat: ": heartbeat\n\n" emitted every 30 s by default
//
// Concurrency: SendEvent / SendComment serialize via the writer's
// mutex; the heartbeat goroutine uses the same path. Safe to call
// from multiple goroutines.

package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	safego "github.com/team-kielo-app/kielo-shared/observe/safego"
)

// StdlibWriter is the chi/net-http equivalent of Writer. It wraps a
// raw http.ResponseWriter, sets the canonical SSE headers, and
// exposes the same SendEvent / SendComment / Start|StopHeartbeat
// API surface so the two writers are interchangeable behind the
// `Streamer` interface below.
type StdlibWriter struct {
	w              http.ResponseWriter
	flusher        http.Flusher
	heartbeatStop  chan struct{}
	heartbeatOnce  sync.Once
	heartbeatDelay time.Duration
	mu             sync.Mutex
}

// NewStdlibWriter creates a new SSE writer for a raw http.ResponseWriter.
//
// Returns an error if the response writer does not implement
// http.Flusher — without flush support, every Write would buffer
// indefinitely and the SSE semantics would silently break. Callers
// should fall back to a non-streaming response in that case.
//
// Headers set:
//   - Content-Type: text/event-stream
//   - Cache-Control: no-cache
//   - Connection: keep-alive
//   - X-Accel-Buffering: no   (disables nginx output buffering)
//
// The headers are flushed by writing an initial comment line so the
// browser / mobile client sees response headers immediately, not after
// the first event.
func NewStdlibWriter(w http.ResponseWriter) (*StdlibWriter, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported: response writer is not an http.Flusher")
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	sw := &StdlibWriter{
		w:              w,
		flusher:        flusher,
		heartbeatStop:  make(chan struct{}),
		heartbeatDelay: 30 * time.Second,
	}

	// Force the response headers out before the handler does any real
	// work so clients see a 200 immediately. Writing the empty comment
	// is the canonical way to flush headers without committing to a
	// payload shape.
	if err := sw.SendComment("connected"); err != nil {
		return nil, fmt.Errorf("initial flush: %w", err)
	}

	return sw, nil
}

// SendEvent sends a named SSE event with JSON-marshaled data.
func (w *StdlibWriter) SendEvent(eventName string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if eventName != "" {
		if _, err := fmt.Fprintf(w.w, "event: %s\n", eventName); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w.w, "data: %s\n\n", jsonData); err != nil {
		return err
	}
	w.flusher.Flush()
	return nil
}

// SendComment writes an SSE comment line. Used for heartbeats and
// for forcing initial header flush.
func (w *StdlibWriter) SendComment(comment string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := fmt.Fprintf(w.w, ": %s\n\n", comment); err != nil {
		return err
	}
	w.flusher.Flush()
	return nil
}

// SendRetry emits the SSE "retry:" directive that tells compliant
// clients how long (ms) to wait before reconnecting after an error.
// Use sparingly — most clients have sensible defaults and forcing a
// very low retry can hammer the server during partial outages.
func (w *StdlibWriter) SendRetry(retryMs int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := fmt.Fprintf(w.w, "retry: %d\n\n", retryMs); err != nil {
		return err
	}
	w.flusher.Flush()
	return nil
}

// StartHeartbeat begins a background goroutine that emits a `:
// heartbeat` comment every heartbeatDelay (default 30 s). The
// heartbeat keeps proxies and mobile carriers from idling out long-
// running streams. Call StopHeartbeat (or just let the request context
// cancel) to stop.
func (w *StdlibWriter) StartHeartbeat() {
	safego.Go("sse_stdlib_heartbeat", func() {
		ticker := time.NewTicker(w.heartbeatDelay)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := w.SendComment("heartbeat"); err != nil {
					return
				}
			case <-w.heartbeatStop:
				return
			}
		}
	})
}

// StopHeartbeat stops the heartbeat goroutine. Idempotent.
func (w *StdlibWriter) StopHeartbeat() {
	w.heartbeatOnce.Do(func() {
		close(w.heartbeatStop)
	})
}

// SetHeartbeatDelay overrides the default 30 s heartbeat cadence.
// Call before StartHeartbeat.
func (w *StdlibWriter) SetHeartbeatDelay(d time.Duration) {
	w.heartbeatDelay = d
}

// Streamer is the minimal interface satisfied by both Writer (Echo)
// and StdlibWriter (chi/raw). Handlers that want to be portable
// between Echo and chi can depend on this interface rather than the
// concrete writer.
type Streamer interface {
	SendEvent(eventName string, data any) error
	SendComment(comment string) error
	StartHeartbeat()
	StopHeartbeat()
}

// compile-time assertions so renaming the interface methods breaks
// at build time rather than at SSE-frame-decoding time.
var (
	_ Streamer = (*Writer)(nil)
	_ Streamer = (*StdlibWriter)(nil)
)
