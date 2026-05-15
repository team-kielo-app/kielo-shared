package localization

import (
	"context"
	"sync"
)

// Metrics receives one Record call per Seam.Translate invocation,
// labeled by namespace, target locale, and the resolution path that
// served the translation. Source values are stable and documented for
// dashboard / alert consumption:
//
//   - "english_passthrough" — target was empty / "en" / source text empty
//   - "override"            — served from OverrideStore.Lookup
//   - "cache_hit"           — fresh cache hit
//   - "cache_swr"           — stale cache hit, background refresh kicked off
//   - "cache_miss_share"    — single-flight share of an in-flight provider call
//   - "provider_call"       — provider invoked successfully, value cached
//   - "provider_error"      — provider unavailable / errored / returned empty
//
// Concrete implementations wire into Prometheus on the consuming
// service side; this shared library ships only the interface +
// noop / in-memory variants so the seam doesn't pull in a Prom client
// transitively.
type Metrics interface {
	Record(ctx context.Context, namespace, targetLocale, source string)
}

// NoopMetrics drops every Record. Default when the consuming service
// hasn't wired Prometheus yet.
type NoopMetrics struct{}

func (NoopMetrics) Record(context.Context, string, string, string) {}

// CountingMetrics is an in-memory Metrics for tests. Lets tests assert
// the seam took exactly the resolution path expected for a given input
// without standing up Prometheus.
type CountingMetrics struct {
	mu     sync.Mutex
	counts map[metricsKey]int
}

type metricsKey struct {
	namespace string
	target    string
	source    string
}

// NewCountingMetrics returns an empty CountingMetrics ready to use.
func NewCountingMetrics() *CountingMetrics {
	return &CountingMetrics{counts: make(map[metricsKey]int)}
}

func (m *CountingMetrics) Record(_ context.Context, namespace, target, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[metricsKey{namespace: namespace, target: target, source: source}]++
}

// Count returns how many times Record was called with the given label
// combination. Zero when never recorded; tests use this to pin the
// resolution path.
func (m *CountingMetrics) Count(namespace, target, source string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[metricsKey{namespace: namespace, target: target, source: source}]
}

// Total returns the sum of every Record call regardless of label.
func (m *CountingMetrics) Total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, n := range m.counts {
		total += n
	}
	return total
}
