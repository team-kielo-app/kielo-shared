package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Notification metrics — Sweep post-ZT-followup-docker Round H Follow-up C
// (2026-06-04). Backfills the 12-metric observability surface enumerated
// in docs/architecture/notification-system-design.md §6.
//
// CARDINALITY BUDGET: every label set must stay bounded. Specifically:
//   - tier ∈ {operational, behavioral, marketing} — 3
//   - type ∈ NotificationType enum — currently 11 (after Round H Follow-up E
//     drained feedback_response). Stays bounded by the closed-set enum.
//   - recipient_model ∈ {user, device, cohort, segment, broadcast} — 5
//   - channel ∈ {push, email, inbox, sse, modal} — 5
//   - locale ∈ supported locales (4 base + extended). Bounded by closed-set.
//   - severity ∈ {critical, warning, info, none} — 4
//   - status ∈ {ok, invalid_token, api_error, bounce, smtp_error,
//     rule_unmatched, dropped} — 7
//   - rule_id: full UUID. **DO NOT include in any high-volume metric** —
//     it would explode cardinality. Only used on the rule-engine
//     match/unmatch counter where the cardinality bound is the count of
//     enabled rules (~12 today; grows linearly with admin curation).
//
// Avoid:
//   - user_id labels: would produce N labels per N users = unbounded.
//   - device_token labels: same.
//   - event_id labels: same.

// ---------------------------------------------------------------------------
// Producer-side metrics (§6 producer block).
// ---------------------------------------------------------------------------

// NotificationProducedTotal counts notification production events by
// tier/type/recipient_model/trigger_source. Surfaces volume per producer
// path independent of downstream dispatch success. Pair with the dispatch
// counters below to spot producer-vs-dispatch ratio anomalies.
//
// Labels:
//   - tier: "operational" | "behavioral" | "marketing"
//   - type: NotificationType wire string (e.g. "purchase_confirmation")
//   - recipient_model: "user" | "device" | "cohort" | "segment" | "broadcast"
//   - trigger_source: short string identifying the producer
//     (e.g. "revenuecat_webhook", "engine_internal_http",
//     "user_action_spine", "admin_broadcast", "recommendation_campaign")
//
// Recommended alerts:
//   - rate-of-change drop > 80% on operational types — silent producer
//   - rate-of-change spike > 5× baseline on broadcast — runaway script
var NotificationProducedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_produced_total",
		Help: "Notification production events by tier/type/recipient_model/trigger_source. " +
			"Pair with dispatch counters for producer↔dispatch ratio.",
	},
	[]string{"tier", "type", "recipient_model", "trigger_source"},
)

// NotificationProduceLatencySeconds buckets notification-event firing →
// dispatch-queue-enter latency. Measures producer overhead BEFORE async
// Pub/Sub or HTTP transport.
//
// Buckets matched to kielo_llm_latency_seconds for dashboard parity.
var NotificationProduceLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_notification_produce_latency_seconds",
		Help:    "Notification producer wall-clock latency (event-firing → dispatch-queue-enter) by tier/type.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	},
	[]string{"tier", "type"},
)

// ---------------------------------------------------------------------------
// Consumer-side metrics — rule engine + job processor (§6 consumer block).
// ---------------------------------------------------------------------------

// NotificationRuleMatchedTotal counts rule-engine event-type matches
// against registered NotificationRules. The rule_id label is bounded by
// the count of active rules (~12 today; grows linearly with admin
// curation, not user traffic).
//
// Labels:
//   - event_type: incoming wire-string event_type
//   - rule_id: UUID of the matched NotificationRule
//
// Recommended alerts:
//   - rate-of-change drop > 80% on a known-busy rule — producer outage
var NotificationRuleMatchedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_rule_matched_total",
		Help: "Rule-engine event_type matches by event_type/rule_id. Surfaces which rules actually fire.",
	},
	[]string{"event_type", "rule_id"},
)

// NotificationRuleUnmatchedTotal counts event_types that flow into the
// rule engine WITHOUT a matching enabled rule. Surfaces dormant rule
// candidates (the ones we have producers for but no rule to dispatch)
// AND producer-typo class events (the event_type literal doesn't exist).
//
// Labels:
//   - event_type: incoming wire-string event_type
//   - allow_direct: "true" | "false" — was the path allowDirect (HTTP)
//     or rule-only (Pub/Sub consumer)? When false, unmatched event_types
//     are silently dropped (no fallback notification).
var NotificationRuleUnmatchedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_rule_unmatched_total",
		Help: "Event_types that enter rule-engine with no matching enabled rule. High counts indicate dormant rules or producer typos.",
	},
	[]string{"event_type", "allow_direct"},
)

// NotificationJobPending is a gauge of pending notification_jobs rows by
// target_type. Sustained growth indicates the JobProcessor is falling
// behind (or stale-running rows from crashed workers — see design doc §5
// Tier-1B item 12).
//
// Labels:
//   - target_type: "user" | "segment" | "all"
//
// Recommended alerts:
//   - any single value > 1000 sustained 5min — backlog
//   - per-bucket growth rate > 0 for > 15min — processor stuck
var NotificationJobPending = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kielo_notification_job_pending",
		Help: "Pending notification_jobs rows by target_type. Track JobProcessor backlog.",
	},
	[]string{"target_type"},
)

// NotificationJobDurationSeconds buckets full job processing duration
// (MarkJobRunning → CompleteJob). High p99 on segment/all targets is
// expected (large cohorts); spike on user-target signals individual
// SendToUser slowness.
var NotificationJobDurationSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_notification_job_duration_seconds",
		Help:    "Notification job processing duration by target_type.",
		Buckets: []float64{0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0},
	},
	[]string{"target_type"},
)

// ---------------------------------------------------------------------------
// Dispatch-side metrics — push (§6 dispatch block).
// ---------------------------------------------------------------------------

// NotificationPushSentTotal counts Expo Push API dispatch outcomes per
// notification type and resolved locale. Tracks the actual delivery
// attempt (not retries, which Pub/Sub handles upstream).
//
// Labels:
//   - type: NotificationType wire string
//   - locale: device-resolved locale (DDDD 3-level COALESCE output)
//   - status: "ok" | "invalid_token" | "api_error"
//   - ok: Expo accepted the push (still may fail at APNs/FCM upstream)
//   - invalid_token: DeviceNotRegistered → token cleanup triggered
//   - api_error: Expo HTTP non-2xx or transport error
//
// Recommended alerts:
//   - invalid_token rate > 5% — token validity issue (mass uninstall?)
//   - api_error rate > 1% sustained — Expo outage
var NotificationPushSentTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_push_sent_total",
		Help: "Push dispatch outcomes by notification type / locale / status (ok|invalid_token|api_error).",
	},
	[]string{"type", "locale", "status"},
)

// NotificationPushInvalidTokenTotal counts dead-token cleanup events.
// Pairs with NotificationPushSentTotal{status=invalid_token} — same
// numerator, different lens: this counter is keyed on REASON for the
// cleanup (Expo's status message classification).
//
// Labels:
//   - reason: "device_not_registered" | "message_too_big" | "rate_limited" |
//     "unknown"
var NotificationPushInvalidTokenTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_push_invalid_token_total",
		Help: "Push dead-token cleanup events by Expo error reason.",
	},
	[]string{"reason"},
)

// ---------------------------------------------------------------------------
// Dispatch-side metrics — email + inbox + SSE (§6 dispatch block, cont'd).
// ---------------------------------------------------------------------------

// NotificationEmailSentTotal counts email dispatch outcomes per
// notification type and locale.
//
// Labels:
//   - type: NotificationType wire string
//   - locale: per-user resolved supportLang
//   - status: "ok" | "bounce" | "smtp_error" | "suppressed"
//   - bounce: SMTP server returned 5xx (TODO: requires SES bounce
//     webhook integration — see design doc §5 Tier-1A item 3)
//   - suppressed: address in suppression list (also TODO)
var NotificationEmailSentTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_email_sent_total",
		Help: "Email dispatch outcomes by notification type / locale / status (ok|bounce|smtp_error|suppressed).",
	},
	[]string{"type", "locale", "status"},
)

// NotificationInboxInsertedTotal counts users.notifications row INSERTs
// (after ON CONFLICT DO NOTHING resolves to true insert). Tracks the
// inbox-side dedup against duplicate dispatch.
//
// Labels:
//   - type: NotificationType wire string
//
// Recommended alerts:
//   - rate-of-change drop > 80% — fanout pipeline outage
var NotificationInboxInsertedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_inbox_inserted_total",
		Help: "Users.notifications row INSERTs (post-dedup) by notification type.",
	},
	[]string{"type"},
)

// NotificationSSESubscriberActive is a gauge of currently-connected SSE
// subscribers per (rough) user segment. Used to size buffer pools and
// detect mass-disconnect events.
//
// Labels:
//   - user_segment: bucketed user identifier (NEVER raw user_id).
//     Recommended bucketing: "authenticated" | "anonymous" | future
//     premium tiers. Keep cardinality <10.
var NotificationSSESubscriberActive = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kielo_notification_sse_subscriber_active",
		Help: "Currently-connected SSE subscribers (gauge) by bucketed user_segment.",
	},
	[]string{"user_segment"},
)

// NotificationSSEDropTotal counts SSE events dropped due to slow
// consumers (the silent 16-slot buffer overflow per design doc §5
// Tier-1A item 2). MUST fire for every drop so operators can see the
// gap; absence of this counter is what made the gap silent pre-Round-H-C.
//
// Labels:
//   - reason: "buffer_full" | "subscriber_disconnected" | "send_timeout"
var NotificationSSEDropTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_sse_drop_total",
		Help: "SSE events dropped to slow consumers by reason. Replaces the pre-Round-H-C silent drop.",
	},
	[]string{"reason"},
)

// ---------------------------------------------------------------------------
// Locale resolution metrics (§6 locale block).
// ---------------------------------------------------------------------------

// NotificationLocaleResolvedTotal counts the source tier where the
// device locale was resolved. The 3-level DDDD COALESCE chain produces
// one of 3 outcomes per dispatched token. Tracks how often each tier
// fires so operators can see DDDD V082 device-language-code adoption
// curve.
//
// Labels:
//   - source: "tier1_device" | "tier2_user" | "tier3_terminal"
//   - tier1_device: pt.device_language_code populated
//   - tier2_user: device_language_code empty/null, u.support_language_code wins
//   - tier3_terminal: both empty/null, fell back to 'en'
//
// Recommended dashboards:
//   - Stacked area chart of tier distribution — visualizes DDDD adoption
//   - High tier3 rate signals Phase 4 not fully rolled out on a device
//     class (legacy push tokens missing device_language_code)
var NotificationLocaleResolvedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_locale_resolved_total",
		Help: "DDDD COALESCE locale resolution source distribution (tier1_device|tier2_user|tier3_terminal).",
	},
	[]string{"source"},
)

// NotificationLocaleFallbackTotal counts cases where the resolved locale
// is missing from a localization registry (push.*, email.*, inbox.*
// keysets) and falls back to a different locale. Tracks localization
// coverage gaps across the 4 base + 13 extended locale surface.
//
// Labels:
//   - from: requested locale (e.g. "vi", "sv")
//   - to: actually-rendered locale (e.g. "en" when 'vi' translation missing)
var NotificationLocaleFallbackTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_notification_locale_fallback_total",
		Help: "Locale resolution fallback events (from→to). High rate of from=vi/sv/fi → to=en signals localization coverage gap.",
	},
	[]string{"from", "to"},
)

// ---------------------------------------------------------------------------
// Maintenance mode metrics (§6 maintenance block).
// ---------------------------------------------------------------------------

// MaintenanceModeActive is a gauge of currently-active maintenance state.
// Set to 1 when the status.json `mode != "ok"`. Distinct labels per
// severity allow alerts to fire differently on critical vs warning.
//
// Labels:
//   - mode: "maintenance" | "degraded"
//   - severity: "critical" | "warning" | "info"
var MaintenanceModeActive = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kielo_maintenance_mode_active",
		Help: "Currently-active maintenance mode state (mode + severity). 1=active, 0=inactive.",
	},
	[]string{"mode", "severity"},
)

// MaintenanceStatusFetchTotal counts public status.json fetch outcomes
// from the mobile side (reported via analytics SSE channel on next
// auth-recovery, OR on cold-boot via standard analytics).
//
// Labels:
//   - result: "ok" | "timeout" | "404" | "parse_error" | "network_error"
var MaintenanceStatusFetchTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_maintenance_status_fetch_total",
		Help: "Public status.json fetch outcomes from client side.",
	},
	[]string{"result"},
)
