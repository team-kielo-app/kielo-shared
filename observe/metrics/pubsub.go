package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PubSubPublishTotal counts Pub/Sub publish attempts by service, topic, and
// outcome (success / error). Used to detect publisher-side failures that
// would otherwise be invisible — kielo-shared/pubsubutil callers swallow
// publish errors today (returning empty message_id) so without this counter
// a wholesale publish outage looks like silence on the consumer side.
//
// Wire-up:
//
//	import sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
//	sharedmetrics.PubSubPublishTotal.WithLabelValues(
//	    "kielolearn-engine", "klearn.lesson-generation.v1", "success",
//	).Inc()
//
// Labels:
//   - service: short service name (e.g. "kielo-cms", "kielolearn-engine")
//   - topic: full topic name as published to (e.g. "klearn.lesson-generation.v1").
//     Keep cardinality bounded — fixed topic-name set, not per-message.
//   - outcome: "success" | "error" | "skipped" (the last covers
//     short-circuit paths — e.g. publisher disabled in dev, batch is empty).
//
// Recommended alerts:
//   - error_rate(service, topic) > 1% over 5min — publisher outage signal.
//   - rate-of-change drop > 80% on a known-busy topic — silent stoppage.
var PubSubPublishTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_pubsub_publish_total",
		Help: "Pub/Sub publish attempts by service/topic/outcome. Detects publisher outages that the per-event log lines miss.",
	},
	[]string{"service", "topic", "outcome"},
)

// PubSubPublishLatencySeconds buckets publish wall-clock latency in
// seconds. Publishes are typically <50ms; sustained p95 >500ms signals a
// Pub/Sub backend or serialization slowdown.
//
// The bucket layout matches kielo_llm_latency_seconds for visual parity
// in dashboards comparing infra-bound vs LLM-bound latency.
var PubSubPublishLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_pubsub_publish_latency_seconds",
		Help:    "Pub/Sub publish wall-clock latency by service/topic.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	},
	[]string{"service", "topic"},
)

// PubSubAckTotal counts Pub/Sub message ack outcomes on the consumer
// side, by service/topic/outcome. Distinct from publish counters so
// dashboards can detect publish/ack imbalance (e.g. publisher healthy
// but consumer lagging or repeatedly nacking).
//
// Labels:
//   - service: short service name of the CONSUMER (push handler or pull
//     subscriber).
//   - topic: source topic.
//   - outcome: "ack" | "nack" | "deadletter" | "drop"
//   - ack: consumer accepted, ack-ed normally.
//   - nack: consumer rejected, will be redelivered (transient error).
//   - deadletter: redelivery exhausted, message routed to DLQ.
//   - drop: consumer accepted (HTTP 2xx) but intentionally discarded —
//     e.g. the Phase X behavioral-event handler that drops
//     missing-language events with a 204+log to avoid loop.
var PubSubAckTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_pubsub_ack_total",
		Help: "Pub/Sub consumer ack outcomes by service/topic/outcome (ack|nack|deadletter|drop).",
	},
	[]string{"service", "topic", "outcome"},
)
