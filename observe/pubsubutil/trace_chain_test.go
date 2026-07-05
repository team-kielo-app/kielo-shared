package pubsubutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// mediaOwnerDeletedEvent is the event_type for the media owner-deleted chain.
// The publisher (kielo-user-service) emits it via EventAttributes and a
// downstream subscriber (kielo-media-processor) consumes it via
// ConsumerContext. These tests prove the trace survives that hop.
const mediaOwnerDeletedEvent = "kielo.media.owner_deleted.v1"

// TestTrace_MediaEventChain_PublishConsumeRoundTrip proves that a trace placed
// on a publisher ctx via the standard EventAttributes recipe survives the
// Pub/Sub publish->consume hop: the consumer continues the SAME trace_id while
// minting its OWN child span_id, recording the producer's span as parent.
func TestTrace_MediaEventChain_PublishConsumeRoundTrip(t *testing.T) {
	// 1. Publisher: ctx carrying a known trace.
	producer := observe.New()
	pubCtx := observe.WithContext(context.Background(), producer)

	// 2. Build the wire attributes via the real publisher recipe.
	attrs := EventAttributes(pubCtx, mediaOwnerDeletedEvent)
	require.NotNil(t, attrs, "EventAttributes returned nil for a traced media event")

	assert.Equal(t, mediaOwnerDeletedEvent, attrs[EventTypeAttribute],
		"event_type must be stamped for subscriber routing")
	assert.Equal(t, producer.TraceID, attrs[attrTraceID],
		"attrs trace_id must equal the producer ctx trace_id")
	assert.Equal(t, producer.SpanID, attrs[attrSpanID],
		"attrs span_id must be the producer's span (the wire carries the producer hop)")
	assert.NotEmpty(t, attrs[attrTraceID], "trace_id must be non-empty on the wire")

	// 3. Consumer: reconstruct ctx from the received attributes.
	conCtx := ConsumerContext(context.Background(), attrs)
	consumer, ok := observe.FromContext(conCtx)
	require.True(t, ok, "ConsumerContext must store a TraceContext on the consumer ctx")

	// Continuity: same trace.
	assert.Equal(t, producer.TraceID, consumer.TraceID,
		"trace_id must be continuous across the publish->consume hop")
	// Child span: consumer mints its own span, not a fresh trace.
	assert.NotEqual(t, producer.SpanID, consumer.SpanID,
		"consumer must mint a child span_id, not reuse the producer's span")
	assert.Equal(t, producer.SpanID, consumer.ParentSpanID,
		"consumer's parent span must be the producer's span (parentage recorded)")
	// RequestID rides along the whole chain.
	assert.Equal(t, producer.RequestID, consumer.RequestID,
		"request_id must propagate end-to-end")

	// Round-trip closure: if the subscriber re-emits a downstream event from
	// conCtx, the same trace_id keeps flowing (continuity beyond one hop).
	reEmit := EventAttributes(conCtx, "kielo.media.cleanup.requested.v1")
	require.NotNil(t, reEmit, "re-emitted downstream attrs must not be nil")
	assert.Equal(t, producer.TraceID, reEmit[attrTraceID],
		"trace_id must survive attrs->ctx->attrs re-emission (multi-hop continuity)")
	assert.Equal(t, consumer.SpanID, reEmit[attrSpanID],
		"re-emitted span_id must be the consumer hop's span, not the producer's")
	assert.NotEqual(t, attrs[attrSpanID], reEmit[attrSpanID],
		"each hop advances the span; downstream span must differ from upstream")
}

// TestTrace_ConsumerContext_NoTraceAttrs_NoPanicNoTrace proves the negative
// path: a media message that arrived with no trace attributes (legacy or
// untraced publisher) does not panic and yields no/empty trace on the
// consumer ctx — the subscriber starts clean rather than inheriting a bogus
// trace.
func TestTrace_ConsumerContext_NoTraceAttrs_NoPanicNoTrace(t *testing.T) {
	assert.NotPanics(t, func() {
		conCtx := ConsumerContext(context.Background(), map[string]string{})

		tc, ok := observe.FromContext(conCtx)
		assert.False(t, ok, "no TraceContext should be stored when attrs carry no trace")
		assert.True(t, tc.IsZero(), "trace read back must be the zero/empty value")
	}, "ConsumerContext must tolerate trace-free attributes without panicking")
}
