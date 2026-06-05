// Package metrics — Prometheus collectors for transactional-outbox
// observability.
//
// Sweep FH.4 Phase 3 (2026-06-05) — closes the queued observability
// gap from FH.4 Phase 2 / C.3:
//
// Pre-FH.4 Phase 3 the admin-action outbox tables (users.admin_action_outbox
// V103 + communications.admin_action_publish_outbox V104) accumulated
// rows with last_error but no metric surfaced the backlog or per-error
// breakdown. Operators had to query the table directly via SQL to spot:
//   - drainer running but failing on every event (publish errors)
//   - drainer dead / paused (unprocessed rows grow unbounded)
//   - per-event-type backlog (single event_type bottlenecks the queue)
//
// Architectural shape:
//   - AdminActionOutboxUnprocessedTotal: GAUGE sampled periodically by
//     the drainer (or a sibling sampler goroutine). Per-table labels
//     (`users.admin_action_outbox` vs `communications.admin_action_publish_outbox`)
//     so operators distinguish source tier.
//   - AdminActionOutboxPublishFailedTotal: COUNTER incremented at the
//     drainer's MarkError site. Labels (event_type, error_class) for
//     per-event breakdown. Cardinality budget: <50 event_types ×
//     ~10 error classes = ~500 series.
//   - AdminActionOutboxRowAgeSeconds: HISTOGRAM observed at processing
//     time (now - row.created_at). Surfaces drainer lag: if p99
//     creeps past hundreds of seconds, the drainer is behind.
//
// Cardinality budget per design doc §6: total metric series ≤2000;
// these 3 metrics add ≤500 series.
package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AdminActionOutboxUnprocessedTotal is the per-table gauge for the
// admin-action outbox backlog. Labels:
//   - table: either "users.admin_action_outbox" (V103, populated by
//     user-service admin handlers) or
//     "communications.admin_action_publish_outbox" (V104, populated
//     by comms-service admin handlers).
//
// Sampled periodically by the drainer (or a sibling sampler goroutine)
// via repo.CountUnprocessed(); the gauge is reset to the freshly-
// observed value each tick. Operators alert on this exceeding a
// threshold (e.g. >500 for >5min indicates drainer dead / paused).
//
// Sweep FH.4 Phase 3 (2026-06-05).
var AdminActionOutboxUnprocessedTotal = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kielo_admin_action_outbox_unprocessed_total",
		Help: "Current count of unprocessed rows in each admin-action outbox table (sampled periodically by the drainer).",
	},
	[]string{"table"},
)

// AdminActionOutboxPublishFailedTotal is the per-(event_type,
// error_class) failure counter. Incremented at the drainer's
// MarkError site each time an outbox row's Pub/Sub publish fails.
//
// Labels:
//   - table: same enum as AdminActionOutboxUnprocessedTotal.
//   - event_type: the typed admin event_type (e.g.
//     admin.subscription_grant.v1, admin.broadcast.v1). Bounded
//     by AllPublishEventTypes (~25 admin-action members).
//   - error_class: coarse category — "publish_timeout",
//     "publish_unavailable", "marshal_error",
//     "permission_denied", "unknown". Bounded by hand-coded
//     classifier in the drainer; ~5 values.
//
// Cardinality: 2 tables × ~25 event_types × ~5 error_classes = ~250
// series max.
//
// Operators alert on a single (event_type, error_class) sustaining
// >1/sec for 5min — this indicates a permanent publish-side issue
// (topic deleted, credentials revoked, etc.) that the drainer can't
// retry past.
//
// Sweep FH.4 Phase 3 (2026-06-05).
var AdminActionOutboxPublishFailedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_admin_action_outbox_publish_failed_total",
		Help: "Lifetime count of admin-action outbox row publish failures, labeled by source table + event_type + error_class.",
	},
	[]string{"table", "event_type", "error_class"},
)

// AdminActionOutboxRowAgeSeconds is the per-event drainer-lag
// histogram. Observed at each MarkAsProcessed (success) AND each
// MarkError (failure) site: the value is now - row.created_at.
//
// Surfaces drainer lag distribution: if p99 creeps past hundreds of
// seconds, the drainer is behind. The success-side histogram captures
// "happy path lag"; the failure-side captures "stuck-and-retrying"
// lag — operators compare the two to distinguish "drainer is slow"
// from "individual rows are stuck".
//
// Buckets tuned for the expected lag distribution:
//   - 0.1, 0.5, 1: sub-second (immediate processing)
//   - 5, 10, 30, 60: tens-of-seconds (normal drainer cadence; 5s tick)
//   - 300, 900, 3600: minutes-to-an-hour (stuck rows)
//   - +Inf: unbounded (catch-all)
//
// Sweep FH.4 Phase 3 (2026-06-05).
var AdminActionOutboxRowAgeSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "kielo_admin_action_outbox_row_age_seconds",
		Help: "Age (now - row.created_at) of admin-action outbox rows at processing time. Labeled by source table + outcome (processed|errored).",
		Buckets: []float64{
			0.1, 0.5, 1, 5, 10, 30, 60, 300, 900, 3600,
		},
	},
	[]string{"table", "outcome"},
)

// AdminActionOutboxTableUserService is the canonical label value
// for the user-service admin-action outbox table (V103).
const AdminActionOutboxTableUserService = "users.admin_action_outbox"

// AdminActionOutboxTableCommunications is the canonical label value
// for the comms-service admin-action outbox publish table (V104).
const AdminActionOutboxTableCommunications = "communications.admin_action_publish_outbox"

// AdminActionOutboxErrorClass values — coarse categorization of
// publish-side failures. Drainer classifies the err string at
// MarkError site and passes the resulting label.
//
// Sweep FH.4 Phase 3 (2026-06-05).
const (
	AdminActionOutboxErrorClassPublishTimeout     = "publish_timeout"
	AdminActionOutboxErrorClassPublishUnavailable = "publish_unavailable"
	AdminActionOutboxErrorClassMarshalError       = "marshal_error"
	AdminActionOutboxErrorClassPermissionDenied   = "permission_denied"
	AdminActionOutboxErrorClassUnknown            = "unknown"
)

// ClassifyAdminActionOutboxError maps a Go error to the coarse
// error_class label. Drainer uses this at MarkError site so the
// classification logic lives in one place rather than scattered
// across user-service + comms-service drainers.
//
// Heuristic: matches well-known error substrings. New error
// patterns surface as "unknown" until classifier is extended.
//
// Sweep FH.4 Phase 3 (2026-06-05).
func ClassifyAdminActionOutboxError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "DeadlineExceeded"),
		strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "i/o timeout"):
		return AdminActionOutboxErrorClassPublishTimeout
	case strings.Contains(msg, "Unavailable"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"):
		return AdminActionOutboxErrorClassPublishUnavailable
	case strings.Contains(msg, "marshal"),
		strings.Contains(msg, "encode"),
		strings.Contains(msg, "json:"):
		return AdminActionOutboxErrorClassMarshalError
	case strings.Contains(msg, "PermissionDenied"),
		strings.Contains(msg, "Unauthenticated"),
		strings.Contains(msg, "permission denied"):
		return AdminActionOutboxErrorClassPermissionDenied
	default:
		return AdminActionOutboxErrorClassUnknown
	}
}
