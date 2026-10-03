package observe

import (
	"context"
	"strings"
)

// StoredTraceID returns the trace_id to persist on a deferred-work row
// (outbox, retry queue) written under ctx, or nil when ctx carries no
// trace. pgx writes a nil *string as NULL.
//
// Deferred rows are published later by a drainer whose own request has an
// unrelated trace. Persisting the writer's trace_id and restoring it with
// [WithStoredTrace] keeps the published event correlated with the request
// that caused it, regardless of which drain tick picks the row up.
func StoredTraceID(ctx context.Context) *string {
	tc, ok := FromContext(ctx)
	if !ok || !validTraceID(tc.TraceID) {
		return nil
	}
	id := tc.TraceID
	return &id
}

// WithStoredTrace returns ctx carrying a fresh span under the stored
// trace_id, for publishing one deferred row. ctx is returned unchanged when
// the stored value is nil or not a valid W3C trace-id (rows written before
// the column existed keep the drain cycle's trace).
func WithStoredTrace(ctx context.Context, traceID *string) context.Context {
	if traceID == nil || !validTraceID(*traceID) {
		return ctx
	}
	tc := New()
	tc.TraceID = *traceID
	return WithContext(ctx, tc)
}

func validTraceID(id string) bool {
	if len(id) != 32 || id == strings.Repeat("0", 32) {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
