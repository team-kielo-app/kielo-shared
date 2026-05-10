package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// LLMCallsTotal counts LLM provider invocations through the
// `kielo-shared/seam/llm` Go-side seam. Mirrors the Python-side
// `kielo_llm_calls_total` family registered in
// `kielo-shared/kielo_shared/observability/metrics.py` so engine
// (Python) and convo (Go) call rates aggregate cleanly under one
// metric name in Prometheus.
//
// Label set is intentionally identical to the Python side:
//   - provider: version-stamped provider id (e.g. "gemini:gemini-3.1-flash-lite-preview").
//   - task: caller-pinned canonical tag (e.g. "convo_hint").
//   - cache_policy: matches Python `LLMRequest.cache_policy` ("none" | "read_write" | "read_only"). Go callers without a cache layer pass "none".
//   - cached: "true" | "false". No cache layer in Go yet → "false".
//   - error: ErrorClass on failure ("timeout" | "http_5xx" | …) OR empty on success.
//
// Recommended alerts: the existing `llm_error_rate_high` policy in
// terraform/alerts.tf already fires on this family and now covers
// Go callers without further wiring.
var LLMCallsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_llm_calls_total",
		Help: "LLM provider call count by provider/task/cache state. Detects provider regressions before user complaints. Shared family with the Python kielo_shared seam.",
	},
	[]string{"provider", "task", "cache_policy", "cached", "error"},
)

// LLMLatencySeconds is the per-call wall-clock latency. Bucket
// layout matches the Python-side family.
var LLMLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_llm_latency_seconds",
		Help:    "LLM provider latency in seconds.",
		Buckets: []float64{0.005, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0, 30.0},
	},
	[]string{"provider", "task", "cached"},
)
