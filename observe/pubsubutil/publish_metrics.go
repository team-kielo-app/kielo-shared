package pubsubutil

import (
	"errors"
	"time"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// PublishOutcome is the canonical outcome label for the
// kielo_pubsub_publish_total counter. Using these constants instead of
// string literals at call sites keeps the metric's label cardinality
// bounded and prevents typo drift across services.
type PublishOutcome string

const (
	PublishOutcomeSuccess PublishOutcome = "success"
	PublishOutcomeError   PublishOutcome = "error"
	// PublishOutcomeSkipped — short-circuit paths (publisher disabled
	// in dev, payload empty, dry_run flag, etc.). Distinct from error
	// so dashboards can separate "couldn't publish" from "deliberately
	// didn't publish".
	PublishOutcomeSkipped PublishOutcome = "skipped"
)

// AckOutcome is the canonical outcome label for kielo_pubsub_ack_total.
// See the metric definition in observe/metrics/pubsub.go for label
// semantics.
type AckOutcome string

const (
	AckOutcomeAck        AckOutcome = "ack"
	AckOutcomeNack       AckOutcome = "nack"
	AckOutcomeDeadletter AckOutcome = "deadletter"
	// AckOutcomeDrop — consumer accepted the delivery (HTTP 2xx) but
	// intentionally discarded it. Phase X behavioral-event handler is
	// the canonical example: missing learning_language_code on the
	// envelope → ack-and-drop with a warn log to avoid Pub/Sub redelivery.
	AckOutcomeDrop AckOutcome = "drop"
)

// RecordPublish records one publish attempt: increments the counter
// keyed by (service, topic, outcome) and observes the latency histogram
// keyed by (service, topic). The combination is the canonical publisher
// telemetry surface — services should call this exactly once per
// `topic.Publish(...)` attempt.
//
// Usage pattern (matches the existing publisher shape across services):
//
//	start := time.Now()
//	result := topic.Publish(ctx, msg)
//	id, err := result.Get(ctx)
//	pubsubutil.RecordPublish("kielo-cms", topicName, err, time.Since(start))
//	if err != nil {
//	    return err
//	}
//
// Safe to call from a deferred outer function — it doesn't allocate a
// new prometheus collector per call (the counters are package-level
// promauto registrations).
func RecordPublish(service, topic string, err error, latency time.Duration) {
	outcome := PublishOutcomeSuccess
	if err != nil {
		outcome = PublishOutcomeError
	}
	sharedmetrics.PubSubPublishTotal.
		WithLabelValues(service, topic, string(outcome)).
		Inc()
	sharedmetrics.PubSubPublishLatencySeconds.
		WithLabelValues(service, topic).
		Observe(latency.Seconds())
}

// RecordPublishSkipped records a deliberate non-publish (e.g. dev mode
// disabled the publisher, dry_run, empty payload). Latency is not
// observed — there was no attempt to time. Distinct from RecordPublish
// so dashboards can separate "we tried and failed" from "we chose not
// to publish".
func RecordPublishSkipped(service, topic string) {
	sharedmetrics.PubSubPublishTotal.
		WithLabelValues(service, topic, string(PublishOutcomeSkipped)).
		Inc()
}

// RecordAck records the outcome of one consumer-side message handling
// attempt. Use this from push handlers (after the HTTP response is
// chosen — 204=ack, 4xx=nack, 5xx=nack-with-redelivery) and pull
// subscribers (alongside `msg.Ack()` / `msg.Nack()`).
//
// outcome must be one of the AckOutcome* constants. The signature
// accepts the typed value (not a raw string) to keep the metric's
// cardinality bounded. Pass an empty AckOutcome to default to
// AckOutcomeAck — the common case.
func RecordAck(service, topic string, outcome AckOutcome) {
	if outcome == "" {
		outcome = AckOutcomeAck
	}
	sharedmetrics.PubSubAckTotal.
		WithLabelValues(service, topic, string(outcome)).
		Inc()
}

// RecordAckErr is a convenience for handlers that derive ack/nack from
// an error: nil → ack, non-nil → nack. errors.Is is supported via the
// caller mapping; this helper does not introspect the error itself.
func RecordAckErr(service, topic string, err error) {
	if errors.Is(err, nil) {
		RecordAck(service, topic, AckOutcomeAck)
		return
	}
	RecordAck(service, topic, AckOutcomeNack)
}
