package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Content Bridge metrics — Arc 1 (2026-06-07). The Bridge reader
// answers "where else has this learner encountered this word/concept?"
// across 4 surface types. See docs/architecture/content-bridge-design.md
// §5 Bucket 1.5 + ADR §3 D7 G3.
//
// CARDINALITY BUDGET: every label must stay bounded.
//
//   - surface ∈ vocab.AllContentBridgeSurfaceTypes — 4 values
//     {article, video_caption, scenario, exercise_prompt}.
//   - language ∈ active learning languages — 2 today (fi, sv);
//     bounded by ADR-001 strict-{fi,sv} contract.
//   - outcome ∈ {hit, empty, error} — 3 values.
//     "hit" = returned ≥1 row.
//     "empty" = surface table returned zero rows for this item_id.
//     "error" = downstream SQL or HTTP failure.
//
// FORBIDDEN labels (would explode cardinality):
//   - item_id (millions of base_words + grammar_concepts).
//   - user_id (every active learner).
//   - paragraph_id / caption_index / scenario_id (per-row identifiers).
//   - request_id / trace_id (per-request unique).
//
// Cardinality bound for the whole module:
//
//   ContentBridgeReadsTotal:      4 × 2 × 3 = 24 series
//   ContentBridgeOrphanItemIDTotal: 4 × 2     = 8 series
//   ContentBridgeReadLatencySeconds: 4 × 2 × N_buckets
//   ContentBridgePaginationOverflowTotal: 4 × 2 = 8 series
//
// All under the kielo-shared metric registry default budget.

// ContentBridgeReadsTotal counts Bridge read requests by surface +
// language + outcome. The canonical observability primitive:
//   - "outcome=hit" volume tells us which surfaces the consumer ACTUALLY
//     uses (Arc 4 popover should drive article + video_caption traffic;
//     exercise_prompt + scenario will stay near-zero in Arc 1).
//   - "outcome=empty" volume tells us which surfaces are queried but
//     yield no rows (expected for scenario + exercise_prompt in Arc 1;
//     would indicate dead-junction in Arcs 2+3 if producers wire but
//     readers still see empty).
//   - "outcome=error" volume must stay near zero in steady state; any
//     sustained non-zero rate is a P0 reliability signal.
var ContentBridgeReadsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_content_bridge_reads_total",
		Help: "Content Bridge read requests by surface + language + outcome (hit|empty|error).",
	},
	[]string{"surface", "language", "outcome"},
)

// ContentBridgeOrphanItemIDTotal counts requests where the queried
// item_id resolves to ZERO rows across ALL queried surfaces. Distinct
// from per-surface "empty": an orphan item_id is one that exists
// nowhere in the index.
//
// Use cases:
//   - Spike = upstream consumer is asking about items the Bridge can't
//     ground. Indicates a vocabulary mismatch or stale upstream cache.
//   - Steady non-zero rate = some item_ids legitimately have no
//     references (e.g. base_words that only appear in archived
//     content). Acceptable; track for trend.
var ContentBridgeOrphanItemIDTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_content_bridge_orphan_item_id_total",
		Help: "Content Bridge requests where item_id resolves to zero rows across all queried surfaces.",
	},
	[]string{"language"},
)

// ContentBridgeReadLatencySeconds tracks the per-request latency of
// the Bridge reader endpoint, bucketed by surface + language.
// Histogram so dashboards can plot p50/p95/p99.
//
// Notification author SLO budget: p99 < 1s (called on the scheduled-
// scanner cadence; not hot path).
// Mobile popover SLO budget (Arc 4 future): p95 < 200ms.
var ContentBridgeReadLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_content_bridge_read_latency_seconds",
		Help:    "Content Bridge read latency by surface + language.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	},
	[]string{"surface", "language"},
)

// ContentBridgePaginationOverflowTotal counts requests where the
// underlying table returned MORE rows than the request's limit AND
// the server returned a next_page_key. Tracks whether consumers are
// hitting the pagination boundary — important signal for when
// notification authors need to be aware of multi-page item references.
//
// Steady > 0 rate is informative, not alarming: popular items
// legitimately have many references.
var ContentBridgePaginationOverflowTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_content_bridge_pagination_overflow_total",
		Help: "Content Bridge requests that returned a non-empty next_page_key (popular item exceeded limit).",
	},
	[]string{"surface", "language"},
)

// AllowedContentBridgeCallers is the bounded set of `caller` label
// values accepted by ContentBridgeReadsByCallerTotal. The handler
// coerces any unknown ?caller= query param to "unknown" before
// emitting the metric, so this set bounds cardinality even when
// callers misuse the API.
//
// When a new consumer wires up, add its canonical caller key here
// AND in the consumer's request construction. Keeping the set
// closed prevents the Sweep ZJ-B class drift where free-form label
// values silently explode cardinality.
//
// Current callers (ratification 2026-06-07):
//
//   - notif_author_b — Author B (new_item_encountered)
//   - notif_author_d — Author D (article_grazing)
//   - notif_author_recurring_difficulty
//   - notif_author_return_after_silence
//   - notif_author_first_week
//   - popover — Arc 4 mobile reader popover
//   - recommender — Arc 5 recommendation engine
//   - admin — operator audits, coverage reports
//   - test — integration tests, smoke probes
//   - unknown — coerced fallback for missing or invalid ?caller=
var AllowedContentBridgeCallers = map[string]struct{}{
	"notif_author_b":                    {},
	"notif_author_d":                    {},
	"notif_author_recurring_difficulty": {},
	"notif_author_return_after_silence": {},
	"notif_author_first_week":           {},
	"popover":                           {},
	"recommender":                       {},
	"admin":                             {},
	"test":                              {},
	"unknown":                           {},
}

// ContentBridgeReadsByCallerTotal counts read requests by caller +
// surface + language + outcome. Separate counter (vs adding `caller`
// to ContentBridgeReadsTotal) because the existing counter's series
// budget is already documented above; adding a 4th label would
// retroactively multiply every existing dashboard query.
//
// Cardinality bound: 10 (callers) × 4 (surfaces) × 2 (languages)
// × 3 (outcomes) = 240 series. Bounded.
var ContentBridgeReadsByCallerTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_content_bridge_reads_by_caller_total",
		Help: "Content Bridge read requests by caller + surface + language + outcome.",
	},
	[]string{"caller", "surface", "language", "outcome"},
)

// NormalizeContentBridgeCaller coerces an arbitrary input string to
// a value in AllowedContentBridgeCallers. Used by the handler to
// bound the `caller` label even when the request supplies a
// freeform or empty value. Returns "unknown" for empty / unknown
// inputs.
func NormalizeContentBridgeCaller(raw string) string {
	if _, ok := AllowedContentBridgeCallers[raw]; ok {
		return raw
	}
	return "unknown"
}
