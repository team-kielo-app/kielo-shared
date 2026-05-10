package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TTSCallsTotal counts TTS provider invocations through the
// `kielo-shared/seam/tts` Go-side seam. Mirrors the Python
// `kielo_llm_calls_total` family layout for visual + alerting parity
// with the LLM seam dashboard.
//
// Labels:
//   - provider: version-stamped provider id (e.g. "openai-tts:tts-1").
//     Splits dashboards across model bumps and provider swaps.
//   - task: caller-pinned canonical tag (e.g. "convo_playback",
//     "convo_message_audio"). One per call-site so per-task SLOs
//     are stable across refactors.
//   - voice: the voice id used. Small bounded set per provider
//     (OpenAI exposes ~5-10 voice ids); safe label.
//   - error: ErrorClass on failure (e.g. "timeout", "http_5xx",
//     "connection") OR empty on success.
//
// Recommended alerts:
//   - error_rate(task) > 1% over 5min → TTS provider degradation,
//     paired with the existing `provider_fallback_total{provider=
//     "openai_tts"}` runtime fallback signal in kielo-convo.
//   - cache-warmth proxy: success_rate by voice — sudden divergence
//     across voice labels points to a per-voice provider regression.
var TTSCallsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_tts_calls_total",
		Help: "TTS provider call count by provider/task/voice/error. Detects provider regressions before user complaints.",
	},
	[]string{"provider", "task", "voice", "error"},
)

// TTSLatencySeconds is the per-call wall-clock latency. Bucket
// layout matches kielo_llm_latency_seconds for dashboard parity.
var TTSLatencySeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "kielo_tts_latency_seconds",
		Help:    "TTS provider latency in seconds.",
		Buckets: []float64{0.005, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0, 30.0},
	},
	[]string{"provider", "task", "voice"},
)
