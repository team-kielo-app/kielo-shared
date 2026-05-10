// Package tts is the Go-side TTS seam.
//
// Mirrors the Python `kielo_shared.llm` seam shape: a narrow Provider
// interface, opt-in decorators (today: metrics; later: cache,
// correlation), and a stable Request/Result/Error vocabulary so
// callers can swap providers without rewriting metric labels or
// circuit-breaker plumbing.
//
// Scope discipline: providers do ONE thing — turn (text, voice,
// speed) into audio bytes. Caching, circuit breakers, scenario
// resolution, voice normalization stay in the caller. The seam is
// the choke point for outbound TTS HTTP traffic, NOT a kitchen sink.
package tts

import (
	"context"
	"errors"
)

// Request is the caller-supplied TTS input. ProviderID is opaque to
// the caller — provided by the Provider impl and round-tripped onto
// Result/metrics so dashboards can split by version / model bump
// without renaming the caller-supplied tags.
type Request struct {
	// Text is the source-language string to synthesize. Required.
	Text string
	// VoiceID is the provider's voice identifier (e.g. OpenAI
	// "alloy", "verse"). Caller is responsible for normalizing /
	// validating before calling the seam. Empty string permitted —
	// providers MAY supply their own default.
	VoiceID string
	// Speed is the playback speed multiplier (typically 0.5..2.0).
	// Provider clamps to its accepted range.
	Speed float64
	// Model is the provider-specific model identifier (e.g.
	// OpenAI "tts-1", "gpt-4o-mini-tts"). Empty ⇒ provider default.
	Model string
	// Instructions is an optional natural-language style hint, used
	// by `gpt-4o-mini-tts` ("speak slowly with a calm tone").
	// Ignored by providers that don't support it.
	Instructions string
	// Task is the canonical seam task tag (snake_case). Pinned per
	// caller for dashboards / alerts. Mirrors the LLM seam's
	// `task` field — keeps observability conventions uniform.
	// Required.
	Task string
}

// Result carries the synthesized audio + provenance the caller
// reflects into its own metrics / cache key / breaker state.
type Result struct {
	// Audio is the raw audio bytes (typically MP3 unless the
	// caller requested a different response_format via Model
	// configuration; future expansion).
	Audio []byte
	// Provider is the version-stamped provider id (e.g.
	// "openai-tts:tts-1"). Round-tripped onto metric labels.
	Provider string
	// LatencyMs is the wall-clock provider-call duration. Caller
	// already gets latency via the metrics decorator's histogram —
	// this is here for callers that want to log it themselves.
	LatencyMs int64
}

// ErrorClass categorizes provider failures. Caller-side circuit
// breakers / retry policies pivot on this so a transient
// `ErrorClassTimeout` triggers backoff while a permanent
// `ErrorClassClientError` skips retry.
type ErrorClass string

const (
	ErrorClassUnknown      ErrorClass = "unknown"
	ErrorClassTimeout      ErrorClass = "timeout"
	ErrorClassConnection   ErrorClass = "connection"
	ErrorClassClientError  ErrorClass = "http_4xx"
	ErrorClassServerError  ErrorClass = "http_5xx"
	ErrorClassReadBody     ErrorClass = "read_body"
	ErrorClassMarshal      ErrorClass = "marshal"
	ErrorClassEmptyResponse ErrorClass = "empty_response"
)

// Error is the seam's standard provider error. Wraps the underlying
// transport / decoding error and tags it with an ErrorClass for
// metric label / breaker / retry decisions.
type Error struct {
	Class ErrorClass
	Err   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return string(e.Class) + ": " + e.Err.Error()
	}
	return string(e.Class)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ClassOf extracts an ErrorClass from any error returned by the
// seam, treating non-seam errors as unknown. Callers use this to
// label metrics and breaker state without type-asserting.
func ClassOf(err error) ErrorClass {
	if err == nil {
		return ""
	}
	var seamErr *Error
	if errors.As(err, &seamErr) {
		return seamErr.Class
	}
	return ErrorClassUnknown
}

// Provider is the narrow seam interface. Implementations MUST be
// safe for concurrent use — `kielo-convo` invokes Synthesize from
// per-request goroutines.
type Provider interface {
	// Synthesize converts req.Text into audio bytes. Provider-side
	// timeouts come from ctx; caller-side breakers from Wrap*
	// decorators.
	Synthesize(ctx context.Context, req Request) (*Result, error)
}
