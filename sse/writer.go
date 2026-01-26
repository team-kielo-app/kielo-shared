package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// Event represents an SSE event
type Event struct {
	Event string      `json:"event,omitempty"`
	Data  interface{} `json:"data"`
	ID    string      `json:"id,omitempty"`
	Retry int         `json:"retry,omitempty"`
}

// Writer provides SSE streaming capabilities
type Writer struct {
	c              echo.Context
	flusher        http.Flusher
	heartbeatStop  chan struct{}
	heartbeatOnce  sync.Once
	heartbeatDelay time.Duration
	mu             sync.Mutex
}

// NewWriter creates a new SSE writer for the given Echo context
func NewWriter(c echo.Context) (*Writer, error) {
	// Set SSE headers
	c.Response().Header().Set("Content-Type", "text/event-stream")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	// Get flusher
	flusher, ok := c.Response().Writer.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

	return &Writer{
		c:              c,
		flusher:        flusher,
		heartbeatStop:  make(chan struct{}),
		heartbeatDelay: 30 * time.Second,
	}, nil
}

// SendEvent sends a named event with JSON data
func (w *Writer) SendEvent(eventName string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Write event name if provided
	if eventName != "" {
		if _, err := fmt.Fprintf(w.c.Response().Writer, "event: %s\n", eventName); err != nil {
			return err
		}
	}

	// Write data
	if _, err := fmt.Fprintf(w.c.Response().Writer, "data: %s\n\n", jsonData); err != nil {
		return err
	}

	w.flusher.Flush()
	return nil
}

// SendComment sends an SSE comment (used for heartbeats)
func (w *Writer) SendComment(comment string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := fmt.Fprintf(w.c.Response().Writer, ": %s\n\n", comment); err != nil {
		return err
	}
	w.flusher.Flush()
	return nil
}

// StartHeartbeat starts sending periodic heartbeat comments to keep the connection alive
func (w *Writer) StartHeartbeat() {
	go func() {
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
	}()
}

// StopHeartbeat stops the heartbeat goroutine
func (w *Writer) StopHeartbeat() {
	w.heartbeatOnce.Do(func() {
		close(w.heartbeatStop)
	})
}

// SetHeartbeatDelay sets the delay between heartbeats
func (w *Writer) SetHeartbeatDelay(d time.Duration) {
	w.heartbeatDelay = d
}

// JobStatusEvent represents a job status update event
type JobStatusEvent struct {
	JobID    string      `json:"job_id"`
	Status   string      `json:"status"`
	Progress int         `json:"progress,omitempty"`
	Message  string      `json:"message,omitempty"`
	Result   interface{} `json:"result,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type ErrorEvent struct {
	JobID       string `json:"job_id,omitempty"`
	Message     string `json:"message"`
	Recoverable bool   `json:"recoverable"`
}

// SendJobStatus sends a job status event
func (w *Writer) SendJobStatus(event JobStatusEvent) error {
	return w.SendEvent("job_status", event)
}

// SendJobProgress sends a job progress event
func (w *Writer) SendJobProgress(jobID string, progress int, message string) error {
	return w.SendEvent("job_progress", JobStatusEvent{
		JobID:    jobID,
		Progress: progress,
		Message:  message,
	})
}

// SendJobComplete sends a job completion event
func (w *Writer) SendJobComplete(jobID string, result interface{}) error {
	return w.SendEvent("job_complete", JobStatusEvent{
		JobID:  jobID,
		Status: "completed",
		Result: result,
	})
}

// SendJobError sends a job error event
func (w *Writer) SendJobError(jobID string, err error) error {
	return w.SendEvent("job_error", JobStatusEvent{
		JobID:  jobID,
		Status: "failed",
		Error:  err.Error(),
	})
}

func (w *Writer) SendError(jobID string, err error, recoverable bool) error {
	return w.SendEvent("error", ErrorEvent{
		JobID:       jobID,
		Message:     err.Error(),
		Recoverable: recoverable,
	})
}
