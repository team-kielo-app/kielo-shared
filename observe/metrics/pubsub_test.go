package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// Pub/Sub publish + ack metrics are part of the same family so dashboards
// can reason about publish-vs-consume imbalance. These tests pin the
// label sets and counter behavior so a downstream dashboard refactor
// can rely on the labels staying stable.

func TestPubSubPublishTotal_Increments(t *testing.T) {
	PubSubPublishTotal.Reset()

	PubSubPublishTotal.WithLabelValues(
		"kielolearn-engine",
		"klearn.lesson-generation.v1",
		"success",
	).Inc()
	PubSubPublishTotal.WithLabelValues(
		"kielolearn-engine",
		"klearn.lesson-generation.v1",
		"error",
	).Inc()

	got := testutil.ToFloat64(PubSubPublishTotal.WithLabelValues(
		"kielolearn-engine", "klearn.lesson-generation.v1", "success",
	))
	assert.Equal(t, float64(1), got)

	got = testutil.ToFloat64(PubSubPublishTotal.WithLabelValues(
		"kielolearn-engine", "klearn.lesson-generation.v1", "error",
	))
	assert.Equal(t, float64(1), got)
}

func TestPubSubAckTotal_DistinctLabelSet(t *testing.T) {
	PubSubAckTotal.Reset()

	PubSubAckTotal.WithLabelValues("kielolearn-engine", "klearn.behavioral", "ack").Inc()
	PubSubAckTotal.WithLabelValues("kielolearn-engine", "klearn.behavioral", "drop").Inc()

	ack := testutil.ToFloat64(PubSubAckTotal.WithLabelValues(
		"kielolearn-engine", "klearn.behavioral", "ack",
	))
	drop := testutil.ToFloat64(PubSubAckTotal.WithLabelValues(
		"kielolearn-engine", "klearn.behavioral", "drop",
	))
	assert.Equal(t, float64(1), ack)
	assert.Equal(t, float64(1), drop)
}

func TestPubSubPublishLatencySeconds_Observe(t *testing.T) {
	PubSubPublishLatencySeconds.Reset()
	PubSubPublishLatencySeconds.WithLabelValues(
		"kielo-cms", "kielo.content-published.v1",
	).Observe(0.123)

	count := testutil.CollectAndCount(PubSubPublishLatencySeconds)
	assert.GreaterOrEqual(t, count, 1, "histogram must register the observation")
}

// TestPubSubMetrics_Names locks the canonical metric names so a future
// rename forces a deliberate dashboard/alert update.
func TestPubSubMetrics_Names(t *testing.T) {
	cases := []struct {
		c      prometheus.Collector
		want   string
		family string
	}{
		{PubSubPublishTotal, "kielo_pubsub_publish_total", "publish"},
		{PubSubAckTotal, "kielo_pubsub_ack_total", "ack"},
		{PubSubPublishLatencySeconds, "kielo_pubsub_publish_latency_seconds", "publish-latency"},
	}
	for _, tc := range cases {
		var name string
		ch := make(chan *prometheus.Desc, 1)
		tc.c.Describe(ch)
		close(ch)
		desc := <-ch
		name = strings.SplitN(desc.String(), `"`, 4)[1]
		assert.Equal(t, tc.want, name, "%s metric name", tc.family)
	}
}
