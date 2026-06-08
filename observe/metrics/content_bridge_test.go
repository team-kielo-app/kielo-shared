package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestContentBridgeMetrics_Names pins the canonical metric names so
// a future rename forces a deliberate dashboard/alert update. Pattern
// matches TestNotificationMetrics_Names + TestPubSubMetrics_Names.
//
// Content Bridge Arc 1 (2026-06-07).
func TestContentBridgeMetrics_Names(t *testing.T) {
	cases := []struct {
		c    prometheus.Collector
		want string
	}{
		{ContentBridgeReadsTotal, "kielo_content_bridge_reads_total"},
		{ContentBridgeOrphanItemIDTotal, "kielo_content_bridge_orphan_item_id_total"},
		{ContentBridgeReadLatencySeconds, "kielo_content_bridge_read_latency_seconds"},
		{ContentBridgePaginationOverflowTotal, "kielo_content_bridge_pagination_overflow_total"},
	}

	// Pin cardinality budget. Adding a new metric requires updating
	// this slice + the ADR + the design doc in lockstep (Layer 43
	// doc-drift discipline).
	const expectedCount = 4
	if len(cases) != expectedCount {
		t.Errorf("cases cardinality %d; expected %d. "+
			"Update lockstep with content-bridge-design.md + content_bridge.go.",
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

// TestContentBridgeReadsTotal_Increments verifies the canonical
// 3-label increment shape. Pattern matches sibling _Increments tests.
func TestContentBridgeReadsTotal_Increments(t *testing.T) {
	ContentBridgeReadsTotal.Reset()

	// Representative surface × language × outcome cells.
	ContentBridgeReadsTotal.WithLabelValues("article", "fi", "hit").Inc()
	ContentBridgeReadsTotal.WithLabelValues("article", "fi", "hit").Inc()
	ContentBridgeReadsTotal.WithLabelValues("video_caption", "fi", "empty").Inc()
	ContentBridgeReadsTotal.WithLabelValues("scenario", "fi", "empty").Inc()
	ContentBridgeReadsTotal.WithLabelValues("exercise_prompt", "sv", "error").Inc()

	assert.InDelta(t, 2.0,
		testutil.ToFloat64(ContentBridgeReadsTotal.WithLabelValues("article", "fi", "hit")),
		0.001)
	assert.InDelta(t, 1.0,
		testutil.ToFloat64(ContentBridgeReadsTotal.WithLabelValues("video_caption", "fi", "empty")),
		0.001)
	assert.InDelta(t, 1.0,
		testutil.ToFloat64(ContentBridgeReadsTotal.WithLabelValues("scenario", "fi", "empty")),
		0.001)
	assert.InDelta(t, 1.0,
		testutil.ToFloat64(ContentBridgeReadsTotal.WithLabelValues("exercise_prompt", "sv", "error")),
		0.001)
}

// TestContentBridgeOrphanItemIDTotal_Increments verifies the orphan
// counter — single-label (language only).
func TestContentBridgeOrphanItemIDTotal_Increments(t *testing.T) {
	ContentBridgeOrphanItemIDTotal.Reset()

	ContentBridgeOrphanItemIDTotal.WithLabelValues("fi").Inc()
	ContentBridgeOrphanItemIDTotal.WithLabelValues("fi").Inc()
	ContentBridgeOrphanItemIDTotal.WithLabelValues("sv").Inc()

	assert.InDelta(t, 2.0,
		testutil.ToFloat64(ContentBridgeOrphanItemIDTotal.WithLabelValues("fi")),
		0.001)
	assert.InDelta(t, 1.0,
		testutil.ToFloat64(ContentBridgeOrphanItemIDTotal.WithLabelValues("sv")),
		0.001)
}

// TestContentBridgePaginationOverflowTotal_Increments verifies the
// pagination overflow counter — 2-label (surface + language).
func TestContentBridgePaginationOverflowTotal_Increments(t *testing.T) {
	ContentBridgePaginationOverflowTotal.Reset()

	ContentBridgePaginationOverflowTotal.WithLabelValues("article", "fi").Inc()
	ContentBridgePaginationOverflowTotal.WithLabelValues("article", "fi").Inc()
	ContentBridgePaginationOverflowTotal.WithLabelValues("video_caption", "fi").Inc()

	assert.InDelta(t, 2.0,
		testutil.ToFloat64(ContentBridgePaginationOverflowTotal.WithLabelValues("article", "fi")),
		0.001)
	assert.InDelta(t, 1.0,
		testutil.ToFloat64(ContentBridgePaginationOverflowTotal.WithLabelValues("video_caption", "fi")),
		0.001)
}
