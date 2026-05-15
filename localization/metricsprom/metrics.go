// Package metricsprom is the Prometheus-backed implementation of
// localization.Metrics. Exposes the counter family
// `kielo_translation_total` so dashboards can slice by namespace,
// target locale, and resolution path.
//
// Lives in its own sub-package so consumers that don't need
// Prometheus telemetry (unit tests, lightweight tools) don't pull in
// the prometheus client. Same "adapter not a registry" stance as
// cacheredis and overridepgx: callers own the prometheus.Registerer
// lifecycle; this package owns the counter shape.
package metricsprom

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/team-kielo-app/kielo-shared/localization"
)

// CounterName is the Prometheus metric name. Documented as a constant so
// dashboards and alerting rules import it instead of re-typing it.
const CounterName = "kielo_translation_total"

// LabelNames are the canonical Prometheus label names for the counter.
// Order matters because prometheus.WithLabelValues takes positional
// args; keep this in sync with the Record method below.
var LabelNames = []string{"namespace", "target_locale", "source"}

// Metrics is the Prometheus-backed localization.Metrics implementation.
//
// Source label values (stable; documented for dashboard / alert
// consumption):
//   - "english_passthrough"
//   - "override"
//   - "cache_hit"
//   - "cache_swr"
//   - "cache_miss_share"
//   - "provider_call"
//   - "provider_error"
//
// See localization.Metrics interface docs for the meaning of each.
type Metrics struct {
	counter *prometheus.CounterVec
}

// New returns a Metrics ready to record. The CounterVec is registered
// against the given Registerer. Returns an error if registration fails
// (e.g. the registerer already has a metric with the same name from a
// different shape) — services should fail loud at startup rather than
// silently degrade telemetry.
func New(registerer prometheus.Registerer) (*Metrics, error) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: CounterName,
			Help: "Localization seam resolution counter. " +
				"Labels: namespace (resource type), target_locale (BCP-47 base), " +
				"source (english_passthrough|override|cache_hit|cache_swr|" +
				"cache_miss_share|provider_call|provider_error).",
		},
		LabelNames,
	)
	if registerer != nil {
		if err := registerer.Register(counter); err != nil {
			// Re-registration of the same shape is OK (allows two seam
			// instances in one process to share the metric); a real
			// registration error returns.
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
					counter = existing
				} else {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}
	return &Metrics{counter: counter}, nil
}

// MustNew is the panic-on-error helper. Use in service init paths
// where registration failure is a fatal config bug.
func MustNew(registerer prometheus.Registerer) *Metrics {
	m, err := New(registerer)
	if err != nil {
		panic(err)
	}
	return m
}

// Record implements localization.Metrics. The context is currently
// unused (the prometheus client doesn't carry context); kept in the
// signature for parity with the interface.
func (m *Metrics) Record(_ context.Context, namespace, targetLocale, source string) {
	if m == nil || m.counter == nil {
		return
	}
	m.counter.WithLabelValues(namespace, targetLocale, source).Inc()
}

// Compile-time assertion that *Metrics satisfies the interface.
var _ localization.Metrics = (*Metrics)(nil)
