package sse

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the SSE writer used by kielo-ingest-processor,
// kielo-content-service, and kielo-cms for job-status streaming. The
// SSE wire format is rigid — the client (EventSource in the mobile
// app + admin UI) parses by textual prefix. Dropping `\n\n`, swapping
// "event:" for "event ", or missing the JSON braces silently breaks
// every real-time progress UI. These tests pin the format.

// flushableRecorder wraps httptest.ResponseRecorder to satisfy the
// http.Flusher interface expected by NewWriter.
type flushableRecorder struct {
	*httptest.ResponseRecorder
	flushed int
}

func (f *flushableRecorder) Flush() { f.flushed++ }

func newWriterWithRecorder(t *testing.T) (*Writer, *flushableRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest("GET", "/stream", nil)
	rec := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	c := e.NewContext(req, rec)
	w, err := NewWriter(c)
	require.NoError(t, err, "NewWriter should succeed with a flushable response")
	return w, rec
}

func TestNewWriter_SetsSSEHeaders(t *testing.T) {
	// Every downstream EventSource client relies on these four
	// headers being exact. text/event-stream is the wire-format
	// discriminator; no-cache prevents stale events; keep-alive
	// stops the connection from being torn down mid-stream;
	// X-Accel-Buffering: no disables nginx's default 8k buffer
	// which would hold events for seconds before flushing.
	_, rec := newWriterWithRecorder(t)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "keep-alive", rec.Header().Get("Connection"))
	assert.Equal(t, "no", rec.Header().Get("X-Accel-Buffering"))
}

func TestSendEvent_ProducesSSEWireFormat(t *testing.T) {
	// The named-event format is `event: <name>\ndata: <json>\n\n`.
	// The trailing double newline is the event-terminator; without it
	// EventSource silently accumulates until the next write.
	w, rec := newWriterWithRecorder(t)
	err := w.SendEvent("job_status", map[string]string{"status": "ready"})
	require.NoError(t, err)

	body := rec.Body.String()
	assert.Contains(t, body, "event: job_status\n")
	assert.Contains(t, body, `data: {"status":"ready"}`+"\n\n")
	assert.GreaterOrEqual(t, rec.flushed, 1,
		"SendEvent must call Flush so the client sees the event immediately")
}

func TestSendEvent_EmptyEventNameEmitsOnlyData(t *testing.T) {
	// When the event name is empty, the "event:" line is omitted and
	// only "data:" is sent. This is the default-event case — the
	// client hears it via its unnamed `onmessage` handler.
	w, rec := newWriterWithRecorder(t)
	err := w.SendEvent("", map[string]string{"k": "v"})
	require.NoError(t, err)

	body := rec.Body.String()
	assert.NotContains(t, body, "event:", "empty event name must omit the event: line")
	assert.Contains(t, body, `data: {"k":"v"}`+"\n\n")
}

func TestSendEvent_MarshalErrorBubblesUp(t *testing.T) {
	// If the caller passes something json.Marshal can't handle (e.g.
	// a channel), the error must surface rather than emit partial
	// garbage into the stream.
	w, _ := newWriterWithRecorder(t)
	err := w.SendEvent("bad", make(chan int))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal data")
}

func TestSendComment_UsesColonPrefixAndDoubleNewline(t *testing.T) {
	// SSE comments start with ": " and are ignored by clients — used
	// for heartbeats to keep the connection alive without firing
	// onmessage. The prefix MUST be ": " (colon space) per spec; any
	// other start would be parsed as a malformed event.
	w, rec := newWriterWithRecorder(t)
	err := w.SendComment("heartbeat")
	require.NoError(t, err)
	assert.Equal(t, ": heartbeat\n\n", rec.Body.String())
	assert.GreaterOrEqual(t, rec.flushed, 1)
}

func TestSendJobStatus_UsesJobStatusEventName(t *testing.T) {
	// Admin UI + mobile listen for specifically-named events. Renaming
	// would break every subscriber pinned to `addEventListener('job_status')`.
	w, rec := newWriterWithRecorder(t)
	err := w.SendJobStatus(JobStatusEvent{
		JobID:  "j-1",
		Status: "running",
	})
	require.NoError(t, err)
	body := rec.Body.String()
	assert.Contains(t, body, "event: job_status\n")
	assert.Contains(t, body, `"job_id":"j-1"`)
	assert.Contains(t, body, `"status":"running"`)
}

func TestSendJobProgress_ObservesOmitemptyTagging(t *testing.T) {
	// JobStatusEvent has json:",omitempty" on Progress, Message,
	// Result, Error — but NOT on Status (intentional: absent status
	// is distinct from empty-string status in the client).
	// SendJobProgress populates JobID/Progress/Message only; this
	// pins which fields appear on the wire and which drop out.
	w, rec := newWriterWithRecorder(t)
	err := w.SendJobProgress("j-2", 42, "halfway")
	require.NoError(t, err)
	body := rec.Body.String()
	assert.Contains(t, body, "event: job_progress\n")
	assert.Contains(t, body, `"job_id":"j-2"`)
	assert.Contains(t, body, `"progress":42`)
	assert.Contains(t, body, `"message":"halfway"`)
	// Status has NO omitempty → empty string is serialized.
	// Document actual behavior so a future `,omitempty` addition is
	// a deliberate choice rather than an accidental contract break.
	assert.Contains(t, body, `"status":""`)
	// Result + Error DO have omitempty → must not appear.
	assert.NotContains(t, body, `"result"`, "empty result must be omitted")
	assert.NotContains(t, body, `"error"`, "empty error must be omitted")
}

func TestSendError_UsesRecoverableFlag(t *testing.T) {
	// The `recoverable` bit tells the client whether to retry. It is
	// NOT tagged omitempty (intentional — `false` is a meaningful
	// signal), so it must always appear in the payload.
	w, rec := newWriterWithRecorder(t)
	err := w.SendError("j-3", assertErr{"boom"}, false)
	require.NoError(t, err)
	body := rec.Body.String()
	assert.Contains(t, body, "event: error\n")
	assert.Contains(t, body, `"message":"boom"`)
	assert.Contains(t, body, `"recoverable":false`)
}

func TestStopHeartbeat_IsIdempotent(t *testing.T) {
	// StopHeartbeat uses sync.Once; calling it twice must not panic
	// on a double-close. Caller-side cleanup paths often defer it AND
	// call it explicitly on error — both must be safe.
	w, _ := newWriterWithRecorder(t)
	w.StopHeartbeat()
	assert.NotPanics(t, func() { w.StopHeartbeat() },
		"StopHeartbeat must be safe to call multiple times")
}

// assertErr is a tiny test-only error with a known message, used so we
// don't need to import an external errors package for one string.
type assertErr struct{ msg string }

func (e assertErr) Error() string { return e.msg }
