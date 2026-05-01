// Package metrics exposes Prometheus collectors shared across Kielo
// services. Use these instead of redeclaring counters in every service so
// dashboards and alerts can target a single canonical metric name.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// LanguageDefaultFallbackTotal counts requests that fell back to the
// legacy default learning language ("fi") because no language was
// resolvable from the request context. Spikes typically indicate a
// regression in upstream language propagation (missing JWT claim,
// dropped header, broken middleware ordering).
//
// Labels:
//   - service: short service name ("cms", "convo", ...)
//   - callsite: stable identifier of the fallback call site
//     ("ai_scenario_generator", "resolve_learning_language_code", ...)
var LanguageDefaultFallbackTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_language_default_fallback_total",
		Help: "Number of legacy default learning-language fallbacks when request context has no resolvable language.",
	},
	[]string{"service", "callsite"},
)
