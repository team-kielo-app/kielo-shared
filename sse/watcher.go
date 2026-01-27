package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// JobWatcher watches a job and streams status updates
type JobWatcher struct {
	jobID       string
	checkFunc   func(ctx context.Context, jobID string) (JobStatusEvent, bool, error)
	interval    time.Duration
	maxDuration time.Duration
	mu          sync.Mutex
	stopped     bool
}

// NewJobWatcher creates a new job watcher
// checkFunc should return (status, isDone, error)
func NewJobWatcher(
	jobID string,
	checkFunc func(ctx context.Context, jobID string) (JobStatusEvent, bool, error),
) *JobWatcher {
	return &JobWatcher{
		jobID:       jobID,
		checkFunc:   checkFunc,
		interval:    1 * time.Second,
		maxDuration: 5 * time.Minute,
	}
}

// SetInterval sets the polling interval for job status checks
func (jw *JobWatcher) SetInterval(d time.Duration) {
	jw.interval = d
}

// SetMaxDuration sets the maximum duration to watch the job
func (jw *JobWatcher) SetMaxDuration(d time.Duration) {
	jw.maxDuration = d
}

// Watch starts watching the job and streams events to the SSE writer
func (jw *JobWatcher) Watch(ctx context.Context, w *Writer) error {
	// Start heartbeat
	w.StartHeartbeat()
	defer w.StopHeartbeat()

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, jw.maxDuration)
	defer cancel()

	ticker := time.NewTicker(jw.interval)
	defer ticker.Stop()

	// Initial check
	if err := jw.checkAndSend(timeoutCtx, w); err != nil {
		return err
	}

	for {
		select {
		case <-timeoutCtx.Done():
			_ = w.SendError(jw.jobID, fmt.Errorf("job watch timeout"), true)
			return nil
		case <-ticker.C:
			jw.mu.Lock()
			if jw.stopped {
				jw.mu.Unlock()
				return nil
			}
			jw.mu.Unlock()

			if err := jw.checkAndSend(timeoutCtx, w); err != nil {
				return err
			}
		}
	}
}

func (jw *JobWatcher) checkAndSend(ctx context.Context, w *Writer) error {
	status, isDone, err := jw.checkFunc(ctx, jw.jobID)
	if err != nil {
		_ = w.SendError(jw.jobID, err, true)
		return nil
	}

	if err := w.SendJobStatus(status); err != nil {
		return err
	}

	if isDone {
		jw.mu.Lock()
		jw.stopped = true
		jw.mu.Unlock()
		return nil
	}

	return nil
}

// Stop stops the job watcher
func (jw *JobWatcher) Stop() {
	jw.mu.Lock()
	defer jw.mu.Unlock()
	jw.stopped = true
}

// PubSubJobWatcher watches for job updates via PubSub
type PubSubJobWatcher struct {
	jobID    string
	updates  chan JobStatusEvent
	done     chan struct{}
	doneOnce sync.Once
}

// NewPubSubJobWatcher creates a watcher that receives updates from a channel
func NewPubSubJobWatcher(jobID string, updates chan JobStatusEvent) *PubSubJobWatcher {
	return &PubSubJobWatcher{
		jobID:   jobID,
		updates: updates,
		done:    make(chan struct{}),
	}
}

// Watch streams updates from the channel to the SSE writer
func (pw *PubSubJobWatcher) Watch(ctx context.Context, w *Writer) error {
	w.StartHeartbeat()
	defer w.StopHeartbeat()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pw.done:
			return nil
		case event, ok := <-pw.updates:
			if !ok {
				return nil
			}
			if err := w.SendJobStatus(event); err != nil {
				return err
			}
			// Check if job is done
			if event.Status == "completed" || event.Status == "failed" {
				return nil
			}
		}
	}
}

// Stop stops the watcher
func (pw *PubSubJobWatcher) Stop() {
	pw.doneOnce.Do(func() {
		close(pw.done)
	})
}

// ParseJobStatusEvent parses a JSON message into a JobStatusEvent
func ParseJobStatusEvent(data []byte) (JobStatusEvent, error) {
	var event JobStatusEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return JobStatusEvent{}, err
	}
	return event, nil
}
