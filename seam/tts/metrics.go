package tts

import (
	"context"
	"time"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// MetricsDecorator wraps a Provider and emits one
// `kielo_tts_calls_total` counter increment + one
// `kielo_tts_latency_seconds` histogram observation per call.
//
// Mirrors the Python LLMMetricsDecorator pattern:
//
//	provider := tts.NewOpenAITTSProvider(apiKey, httpClient)
//	provider := tts.WithMetrics(provider)
//
// Labels:
//   - provider: round-tripped from the inner provider's ID (e.g.
//     "openai-tts:tts-1") — splits dashboards by model version
//   - task: the caller-supplied seam task tag
//   - voice: the voice id used (bounded set; ~5-10 per provider)
//   - error: ErrorClass on failure, "" on success — same convention
//     as kielo_llm_calls_total{error}
//
// Cardinality controls: voice is the only label that pulls in
// caller-supplied data, but it's a small fixed set per provider.
// task is caller-pinned (one per call site). Provider is a small
// version-stamped list. error is the bounded ErrorClass enum.
type MetricsDecorator struct {
	Inner       Provider
	ProviderTag func(Request) string
}

// WithMetrics is the recommended constructor — derives the provider
// label from the inner's ProviderID(req) when available, falling
// back to a typed fingerprint otherwise.
func WithMetrics(inner Provider) *MetricsDecorator {
	dec := &MetricsDecorator{Inner: inner}
	if p, ok := inner.(interface{ ProviderID(Request) string }); ok {
		dec.ProviderTag = p.ProviderID
	} else {
		dec.ProviderTag = func(_ Request) string {
			return "tts:unknown"
		}
	}
	return dec
}

func (d *MetricsDecorator) Synthesize(ctx context.Context, req Request) (*Result, error) {
	provider := d.ProviderTag(req)
	task := req.Task
	if task == "" {
		task = "generic"
	}
	voice := req.VoiceID
	if voice == "" {
		voice = "default"
	}

	started := time.Now()
	result, err := d.Inner.Synthesize(ctx, req)
	elapsed := time.Since(started).Seconds()

	errLabel := ""
	if err != nil {
		errLabel = string(ClassOf(err))
	}

	sharedmetrics.TTSCallsTotal.WithLabelValues(provider, task, voice, errLabel).Inc()
	sharedmetrics.TTSLatencySeconds.WithLabelValues(provider, task, voice).Observe(elapsed)

	return result, err
}
