package llm

import (
	"context"
	"time"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// MetricsDecorator wraps a Provider and emits one
// `kielo_llm_calls_total` increment + one `kielo_llm_latency_seconds`
// observation per call. Label set matches the Python-side family so
// dashboards aggregate Go + Python callers under one metric name.
type MetricsDecorator struct {
	Inner       Provider
	ProviderTag func(Request) string
}

// WithMetrics is the recommended constructor. Mirrors
// tts.WithMetrics — derives the `provider` label from the inner's
// ProviderID(req) when available.
func WithMetrics(inner Provider) *MetricsDecorator {
	dec := &MetricsDecorator{Inner: inner}
	if p, ok := inner.(interface{ ProviderID(Request) string }); ok {
		dec.ProviderTag = p.ProviderID
	} else {
		dec.ProviderTag = func(_ Request) string {
			return "llm:unknown"
		}
	}
	return dec
}

func (d *MetricsDecorator) Generate(ctx context.Context, req Request) (*Result, error) {
	provider := d.ProviderTag(req)
	task := req.Task
	if task == "" {
		task = "generic"
	}

	// Go-side seam has no cache layer yet — keep label parity with
	// the Python-side family by emitting "none" / "false" so a
	// Prometheus query that aggregates by label across processes
	// doesn't produce two parallel series for the same task.
	cachePolicy := "none"
	cached := "false"

	started := time.Now()
	result, err := d.Inner.Generate(ctx, req)
	elapsed := time.Since(started).Seconds()

	errLabel := ""
	if err != nil {
		errLabel = string(ClassOf(err))
	}

	sharedmetrics.LLMCallsTotal.WithLabelValues(provider, task, cachePolicy, cached, errLabel).Inc()
	sharedmetrics.LLMLatencySeconds.WithLabelValues(provider, task, cached).Observe(elapsed)

	return result, err
}
