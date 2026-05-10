package pubsubutil

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

func TestRecordPublish_SuccessAndError(t *testing.T) {
	sharedmetrics.PubSubPublishTotal.Reset()

	RecordPublish("kielo-cms", "topic-a", nil, 12*time.Millisecond)
	RecordPublish("kielo-cms", "topic-a", errors.New("boom"), 20*time.Millisecond)

	successCount := testutil.ToFloat64(sharedmetrics.PubSubPublishTotal.WithLabelValues(
		"kielo-cms", "topic-a", string(PublishOutcomeSuccess),
	))
	errorCount := testutil.ToFloat64(sharedmetrics.PubSubPublishTotal.WithLabelValues(
		"kielo-cms", "topic-a", string(PublishOutcomeError),
	))
	assert.Equal(t, float64(1), successCount)
	assert.Equal(t, float64(1), errorCount)
}

func TestRecordPublishSkipped_DistinctOutcome(t *testing.T) {
	sharedmetrics.PubSubPublishTotal.Reset()

	RecordPublishSkipped("kielolearn-engine", "topic-b")
	RecordPublishSkipped("kielolearn-engine", "topic-b")

	got := testutil.ToFloat64(sharedmetrics.PubSubPublishTotal.WithLabelValues(
		"kielolearn-engine", "topic-b", string(PublishOutcomeSkipped),
	))
	assert.Equal(t, float64(2), got)
}

func TestRecordAck_DefaultIsAck(t *testing.T) {
	sharedmetrics.PubSubAckTotal.Reset()

	// Empty outcome should default to "ack" — the common path for
	// handlers that just call RecordAck(svc, topic, "") on the happy
	// path.
	RecordAck("kielo-comms", "comm.events", "")
	RecordAck("kielo-comms", "comm.events", AckOutcomeNack)
	RecordAck("kielo-comms", "comm.events", AckOutcomeDeadletter)
	RecordAck("kielo-comms", "comm.events", AckOutcomeDrop)

	for label, want := range map[AckOutcome]float64{
		AckOutcomeAck:        1,
		AckOutcomeNack:       1,
		AckOutcomeDeadletter: 1,
		AckOutcomeDrop:       1,
	} {
		got := testutil.ToFloat64(sharedmetrics.PubSubAckTotal.WithLabelValues(
			"kielo-comms", "comm.events", string(label),
		))
		assert.Equalf(t, want, got, "ack outcome %s", label)
	}
}

func TestRecordAckErr_MapsNilToAckAndErrToNack(t *testing.T) {
	sharedmetrics.PubSubAckTotal.Reset()

	RecordAckErr("kielo-engine", "klearn.x", nil)
	RecordAckErr("kielo-engine", "klearn.x", errors.New("transient"))
	RecordAckErr("kielo-engine", "klearn.x", errors.New("another"))

	ack := testutil.ToFloat64(sharedmetrics.PubSubAckTotal.WithLabelValues(
		"kielo-engine", "klearn.x", string(AckOutcomeAck),
	))
	nack := testutil.ToFloat64(sharedmetrics.PubSubAckTotal.WithLabelValues(
		"kielo-engine", "klearn.x", string(AckOutcomeNack),
	))
	assert.Equal(t, float64(1), ack)
	assert.Equal(t, float64(2), nack)
}

func TestRecordPublish_ObservesLatency(t *testing.T) {
	sharedmetrics.PubSubPublishLatencySeconds.Reset()

	RecordPublish("kielo-cms", "topic-c", nil, 25*time.Millisecond)
	count := testutil.CollectAndCount(sharedmetrics.PubSubPublishLatencySeconds)
	assert.GreaterOrEqual(t, count, 1)
}
