package metrics

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PerLanguageSearchPathFallbackTotal counts SET LOCAL search_path
// resolutions that fell back to the connection-level static path because
// no active learning language was attached to the request context.
// Mirrors the Python-side counter
// `kielo_per_language_search_path_fallback_total` exposed by
// `kielo_shared.observability.metrics` — same name + label vocabulary
// so dashboards aggregate Python (kielolearn-engine, kielo-ingest-processor)
// and Go (kielo-cms, kielo-content-service, kielo-user-service, ...)
// callers under one metric.
//
// The fallback IS the documented contract for background workers
// operating on shared / legacy schemas; on request-path resolvers
// (FastAPI / Echo / Fiber repos that serve user traffic) any non-zero
// rate is a regression in upstream language propagation (missing JWT
// claim, dropped header, broken middleware ordering — the same failure
// modes as kielo_language_default_fallback_total but one layer deeper).
//
// Labels:
//   - service: short service name pinned per process via
//     SetServiceName ("kielo-cms", "kielo-content-service", ...).
//     Defaults to "unknown" if no service has wired it.
//   - callsite: stable identifier of the fallback call site
//     ("apply_search_path_to_tx", "begin_tx_with_search_path", or
//     a finer per-repository tag attached via
//     `kielo-shared/db.WithFallbackCallsite`). Bounded.
//
// Recommended alerts:
//
//	rate(kielo_per_language_search_path_fallback_total{service="kielo-cms"}[5m]) > 0
//	  → middleware regression; investigate via the per-callsite split.
//	{service="unknown"}
//	  → a Go service started using ApplySearchPathToTx without calling
//	    metrics.SetServiceName at boot; wire it.
var PerLanguageSearchPathFallbackTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_per_language_search_path_fallback_total",
		Help: "SET LOCAL search_path resolutions that fell back to the connection-level static path because no active language was on the request context.",
	},
	[]string{"service", "callsite"},
)

// serviceName carries the process-wide service label for
// PerLanguageSearchPathFallbackTotal. Stored as atomic.Value so callers
// can set it once from main() without holding a mutex on every emit.
// Empty string means "no service has wired SetServiceName" — the emit
// helper substitutes "unknown" so the metric still exports.
var serviceName atomic.Value

// SetServiceName pins the service label used by
// PerLanguageSearchPathFallbackTotal. Call once near the top of main(),
// before any DB transaction can fire:
//
//	func main() {
//	    metrics.SetServiceName("kielo-cms")
//	    // ... continue with DB setup, server boot, etc.
//	}
//
// Subsequent calls overwrite the previous value (last-write-wins);
// services that re-init for tests can reset between runs.
func SetServiceName(name string) {
	serviceName.Store(name)
}

// ServiceName returns the value pinned by SetServiceName, or "unknown"
// if no service has wired one. Exposed so the emit helper isn't the
// only reader; callers that already know their service name should
// pass it as a literal rather than read it here.
func ServiceName() string {
	if v, ok := serviceName.Load().(string); ok && v != "" {
		return v
	}
	return "unknown"
}

// fallbackWarnSeen memoizes the (service, callsite) pairs that have
// already produced a WARN log via PerLanguageSearchPathFallbackEmit,
// so the first occurrence catches a human's eye and subsequent ones
// fall to DEBUG. Process-local; the metric is the durable signal,
// and a fresh process re-warns once per pair on cold start.
var (
	fallbackWarnSeen = make(map[fallbackKey]struct{})
	fallbackWarnMu   sync.Mutex
)

type fallbackKey struct {
	service  string
	callsite string
}

// PerLanguageSearchPathFallbackEmit records one search_path fallback
// event. Mirrors the Python-side `per_language_search_path_fallback_emit`:
//
//   - increments PerLanguageSearchPathFallbackTotal{service, callsite}
//     every time.
//   - logs at WARN on the FIRST call for a given (service, callsite)
//     when expectedFallback is false, then at DEBUG thereafter. Used by
//     request-path resolvers where a single fallback already signals
//     upstream regression.
//   - logs at DEBUG every time when expectedFallback is true. Used by
//     background workers / maintenance helpers where fallback IS the
//     documented contract.
//
// callsite is the per-repo tag (default "" → "unknown" — see
// kielo-shared/db.FallbackCallsiteFromContext). service is read from
// the process-global pin set by SetServiceName.
func PerLanguageSearchPathFallbackEmit(callsite string, expectedFallback bool) {
	service := ServiceName()
	if callsite == "" {
		callsite = "unknown"
	}
	if expectedFallback {
		slog.Debug(
			"per_language_search_path_fallback",
			"service", service,
			"callsite", callsite,
			"expected", true,
		)
	} else {
		key := fallbackKey{service: service, callsite: callsite}
		fallbackWarnMu.Lock()
		_, seen := fallbackWarnSeen[key]
		if !seen {
			fallbackWarnSeen[key] = struct{}{}
		}
		fallbackWarnMu.Unlock()
		if !seen {
			slog.Warn(
				"per_language_search_path_fallback: no active language on context; "+
					"using connection-level search_path. Request-path callers should "+
					"always have a language scoped by middleware.",
				"service", service,
				"callsite", callsite,
			)
		} else {
			slog.Debug(
				"per_language_search_path_fallback",
				"service", service,
				"callsite", callsite,
				"expected", false,
			)
		}
	}
	PerLanguageSearchPathFallbackTotal.WithLabelValues(service, callsite).Inc()
}

// ResetPerLanguageSearchPathFallbackState clears the WARN-once memo and
// the counter samples. TEST-ONLY helper, exported so tests in other
// packages (kielo-shared/db, service integration tests) can reset
// between cases without reaching into unexported state.
func ResetPerLanguageSearchPathFallbackState() {
	fallbackWarnMu.Lock()
	fallbackWarnSeen = make(map[fallbackKey]struct{})
	fallbackWarnMu.Unlock()
	PerLanguageSearchPathFallbackTotal.Reset()
}
