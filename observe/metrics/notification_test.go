package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestNotificationMetrics_Names locks the canonical metric names so a
// future rename forces a deliberate dashboard/alert update. Pattern
// matches TestPubSubMetrics_Names in pubsub_test.go.
//
// Sweep post-ZT-followup-docker Round H Follow-up C (2026-06-04).
func TestNotificationMetrics_Names(t *testing.T) {
	cases := []struct {
		c    prometheus.Collector
		want string
	}{
		// Producer-side
		{NotificationProducedTotal, "kielo_notification_produced_total"},
		{NotificationProduceLatencySeconds, "kielo_notification_produce_latency_seconds"},
		// Consumer-side (rule engine + job processor)
		{NotificationRuleMatchedTotal, "kielo_notification_rule_matched_total"},
		{NotificationRuleUnmatchedTotal, "kielo_notification_rule_unmatched_total"},
		{NotificationJobPending, "kielo_notification_job_pending"},
		{NotificationJobDurationSeconds, "kielo_notification_job_duration_seconds"},
		// Dispatch-side (push)
		{NotificationPushSentTotal, "kielo_notification_push_sent_total"},
		{NotificationPushInvalidTokenTotal, "kielo_notification_push_invalid_token_total"},
		// Dispatch-side (email + inbox + SSE)
		{NotificationEmailSentTotal, "kielo_notification_email_sent_total"},
		{NotificationInboxInsertedTotal, "kielo_notification_inbox_inserted_total"},
		// Sweep B3 (2026-06-04): closes design doc §5 Tier-2 #14 gaps.
		{NotificationInboxUnreadCount, "kielo_notification_inbox_unread_count"},
		{NotificationDispatchLatencySeconds, "kielo_notification_dispatch_latency_seconds"},
		{NotificationSSESubscriberActive, "kielo_notification_sse_subscriber_active"},
		{NotificationSSEDropTotal, "kielo_notification_sse_drop_total"},
		// Locale resolution
		{NotificationLocaleResolvedTotal, "kielo_notification_locale_resolved_total"},
		{NotificationLocaleFallbackTotal, "kielo_notification_locale_fallback_total"},
		// Maintenance mode
		{MaintenanceModeActive, "kielo_maintenance_mode_active"},
		{MaintenanceStatusFetchTotal, "kielo_maintenance_status_fetch_total"},
	}

	// Pin cardinality budget. Sweep B3 (2026-06-04) added 2 metrics
	// closing design doc §5 Tier-2 #14 (16 → 18). Adding a new metric
	// requires updating this slice + the design doc in lockstep
	// (Layer 43 doc-drift discipline).
	const expectedCount = 18
	if len(cases) != expectedCount {
		t.Errorf("cases cardinality %d; expected %d. "+
			"Update lockstep with design doc §6 + notification.go.",
			len(cases), expectedCount)
	}

	for _, tc := range cases {
		ch := make(chan *prometheus.Desc, 1)
		tc.c.Describe(ch)
		close(ch)
		desc := <-ch
		name := strings.SplitN(desc.String(), `"`, 4)[1]
		assert.Equal(t, tc.want, name, "metric name")
	}
}

// TestNotificationProducedTotal_Increments verifies the canonical
// producer-side label set increments correctly. Pattern matches
// TestPubSubPublishTotal_Increments.
func TestNotificationProducedTotal_Increments(t *testing.T) {
	NotificationProducedTotal.Reset()

	// Representative tiers + types from each architectural tier per
	// design doc §1 taxonomy.
	NotificationProducedTotal.WithLabelValues(
		"operational", "purchase_confirmation", "user", "revenuecat_webhook",
	).Inc()
	NotificationProducedTotal.WithLabelValues(
		"operational", "achievement", "user", "user_action_spine",
	).Inc()
	NotificationProducedTotal.WithLabelValues(
		"marketing", "recommendation", "cohort", "recommendation_campaign",
	).Inc()
	NotificationProducedTotal.WithLabelValues(
		"operational", "system_updates", "broadcast", "admin_broadcast",
	).Inc()

	// Verify each combo increments independently.
	got := testutil.ToFloat64(NotificationProducedTotal.WithLabelValues(
		"operational", "purchase_confirmation", "user", "revenuecat_webhook",
	))
	assert.Equal(t, float64(1), got)

	got = testutil.ToFloat64(NotificationProducedTotal.WithLabelValues(
		"operational", "system_updates", "broadcast", "admin_broadcast",
	))
	assert.Equal(t, float64(1), got)

	got = testutil.ToFloat64(NotificationProducedTotal.WithLabelValues(
		"marketing", "recommendation", "cohort", "recommendation_campaign",
	))
	assert.Equal(t, float64(1), got)
}

// TestNotificationLocaleResolvedTotal_DDDDTierDistribution exercises the
// DDDD 3-tier COALESCE chain labels. Each tier label must work as a
// dimension; dashboards stack-chart this.
func TestNotificationLocaleResolvedTotal_DDDDTierDistribution(t *testing.T) {
	NotificationLocaleResolvedTotal.Reset()

	// Simulate Tier 1 (per-device language populated) dominant in the
	// post-DDDD-V082 steady state.
	for i := 0; i < 100; i++ {
		NotificationLocaleResolvedTotal.WithLabelValues("tier1_device").Inc()
	}
	// Tier 2 (per-user fallback) less common.
	for i := 0; i < 20; i++ {
		NotificationLocaleResolvedTotal.WithLabelValues("tier2_user").Inc()
	}
	// Tier 3 (terminal 'en') rarest.
	for i := 0; i < 5; i++ {
		NotificationLocaleResolvedTotal.WithLabelValues("tier3_terminal").Inc()
	}

	tier1 := testutil.ToFloat64(NotificationLocaleResolvedTotal.WithLabelValues("tier1_device"))
	tier2 := testutil.ToFloat64(NotificationLocaleResolvedTotal.WithLabelValues("tier2_user"))
	tier3 := testutil.ToFloat64(NotificationLocaleResolvedTotal.WithLabelValues("tier3_terminal"))

	assert.Equal(t, float64(100), tier1)
	assert.Equal(t, float64(20), tier2)
	assert.Equal(t, float64(5), tier3)
	// Pin the expected distribution shape: tier1 should dominate in
	// healthy production post-DDDD adoption.
	assert.Greater(t, tier1, tier2, "tier1 should dominate")
	assert.Greater(t, tier2, tier3, "tier2 should exceed tier3 terminal fallback")
}

// TestNotificationPushSentTotal_StatusLabels exercises the 3-status
// label set (ok | invalid_token | api_error) so dashboards can stack
// chart the dispatch outcome distribution per locale.
func TestNotificationPushSentTotal_StatusLabels(t *testing.T) {
	NotificationPushSentTotal.Reset()

	// Simulate dispatch outcomes across 2 locales × 3 statuses.
	NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "ok").Inc()
	NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "ok").Inc()
	NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "vi", "ok").Inc()
	NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "invalid_token").Inc()
	NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "api_error").Inc()

	okEN := testutil.ToFloat64(NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "ok"))
	okVI := testutil.ToFloat64(NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "vi", "ok"))
	invalidEN := testutil.ToFloat64(NotificationPushSentTotal.WithLabelValues("purchase_confirmation", "en", "invalid_token"))

	assert.Equal(t, float64(2), okEN)
	assert.Equal(t, float64(1), okVI)
	assert.Equal(t, float64(1), invalidEN)
}

// TestNotificationJobPending_GaugeSetClear verifies the gauge can be
// set + cleared by target_type. Pattern: JobProcessor updates the gauge
// on each tick after counting pending rows.
func TestNotificationJobPending_GaugeSetClear(t *testing.T) {
	NotificationJobPending.Reset()

	NotificationJobPending.WithLabelValues("user").Set(42)
	NotificationJobPending.WithLabelValues("segment").Set(7)
	NotificationJobPending.WithLabelValues("all").Set(1)

	user := testutil.ToFloat64(NotificationJobPending.WithLabelValues("user"))
	segment := testutil.ToFloat64(NotificationJobPending.WithLabelValues("segment"))
	all := testutil.ToFloat64(NotificationJobPending.WithLabelValues("all"))

	assert.Equal(t, float64(42), user)
	assert.Equal(t, float64(7), segment)
	assert.Equal(t, float64(1), all)

	// Re-set to verify gauge replaces (doesn't accumulate).
	NotificationJobPending.WithLabelValues("user").Set(0)
	user = testutil.ToFloat64(NotificationJobPending.WithLabelValues("user"))
	assert.Equal(t, float64(0), user)
}

// TestMaintenanceModeActive_SeverityDistinction verifies severity is
// properly broken out as a dimension so alerts can fire differently for
// critical vs warning.
func TestMaintenanceModeActive_SeverityDistinction(t *testing.T) {
	MaintenanceModeActive.Reset()

	// Active critical outage.
	MaintenanceModeActive.WithLabelValues("maintenance", "critical").Set(1)
	// Active warning notice.
	MaintenanceModeActive.WithLabelValues("degraded", "warning").Set(1)
	// Inactive info banner.
	MaintenanceModeActive.WithLabelValues("degraded", "info").Set(0)

	critical := testutil.ToFloat64(MaintenanceModeActive.WithLabelValues("maintenance", "critical"))
	warning := testutil.ToFloat64(MaintenanceModeActive.WithLabelValues("degraded", "warning"))
	info := testutil.ToFloat64(MaintenanceModeActive.WithLabelValues("degraded", "info"))

	assert.Equal(t, float64(1), critical)
	assert.Equal(t, float64(1), warning)
	assert.Equal(t, float64(0), info)
}

// TestNotificationMetrics_HelpText pins the convention that every
// metric carries a non-empty Help line. Helps surface oversights at PR
// time before they ship as cryptic dashboards.
func TestNotificationMetrics_HelpText(t *testing.T) {
	collectors := []prometheus.Collector{
		NotificationProducedTotal,
		NotificationProduceLatencySeconds,
		NotificationRuleMatchedTotal,
		NotificationRuleUnmatchedTotal,
		NotificationJobPending,
		NotificationJobDurationSeconds,
		NotificationPushSentTotal,
		NotificationPushInvalidTokenTotal,
		NotificationEmailSentTotal,
		NotificationInboxInsertedTotal,
		NotificationSSESubscriberActive,
		NotificationSSEDropTotal,
		NotificationLocaleResolvedTotal,
		NotificationLocaleFallbackTotal,
		MaintenanceModeActive,
		MaintenanceStatusFetchTotal,
	}
	for _, c := range collectors {
		ch := make(chan *prometheus.Desc, 1)
		c.Describe(ch)
		close(ch)
		desc := <-ch
		descStr := desc.String()
		// Help text appears after the metric name within Desc.String();
		// look for `help: ""` shape that signals empty.
		assert.False(t, strings.Contains(descStr, `help: ""`),
			"metric %q must have non-empty Help: got %s", descStr, descStr)
	}
}
