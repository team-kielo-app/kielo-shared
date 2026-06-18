// Package llm is the Go-side LLM seam.
//
// Sister of the TTS seam (`kielo-shared/seam/tts`) and a partial mirror
// of the Python `kielo_shared.llm` package. Same scope discipline:
// providers do ONE thing — turn a prompt + (optional) response schema
// into raw model output. Caching, breakers, retry, prompt-rendering
// live in the caller.
//
// Vertical slice today:
//   - GeminiJSONProvider — generativelanguage.googleapis.com structured
//     JSON output (responseMimeType=application/json + responseSchema).
//   - MetricsDecorator   — emits `kielo_llm_calls_total` and
//     `kielo_llm_latency_seconds` mirroring the Python-side label
//     shape so dashboards can aggregate across processes.
package llm

import (
	"context"
	"errors"
)

// Request is the caller-supplied LLM input.
type Request struct {
	// SystemPrompt is the optional system-instruction body
	// (Gemini's `system_instruction.parts.text`). Providers that
	// don't support a separate system channel inline it into the
	// prompt automatically.
	SystemPrompt string
	// Prompt is the user-content body sent to the model. Caller
	// is responsible for templating — the seam stays neutral on
	// prompt strategy.
	Prompt string
	// Model is the provider-specific model id (e.g. for Gemini
	// "gemini-3.1-flash-lite"). Empty ⇒ provider default.
	Model string
	// ResponseSchema is an optional JSON Schema; providers that
	// support structured output (Gemini's responseSchema, OpenAI's
	// response_format=json_schema) enforce it. Providers that
	// don't support structured output ignore the field and return
	// raw text.
	ResponseSchema map[string]any
	// ResponseMimeType is an optional structured-output declaration
	// that doesn't require a full JSON Schema. Providers that
	// support it (Gemini's `generationConfig.responseMimeType`)
	// pass it through; others ignore. Caller convention is
	// "application/json" for JSON-output prompts that hand-build
	// the schema in the prompt body itself.
	ResponseMimeType string
	// Temperature is the sampling temperature. nil ⇒ provider
	// default; explicit 0 (deterministic) requires a non-nil
	// pointer — use `Temp(0)` from this package.
	Temperature *float64
	// Task is the canonical seam task tag (snake_case). Mirrors the
	// Python LLM seam's `task` label so cross-service dashboards
	// can pivot on a single label vocabulary. Required.
	Task string
}

// Temp is a convenience constructor for the optional temperature
// field. Use `llm.Temp(0)` for deterministic prompts and
// `llm.Temp(0.7)` for caller-tuned creativity.
func Temp(v float64) *float64 { return &v }

// Result carries the raw model output + provenance.
type Result struct {
	// RawText is the model's response body. For JSON-schema
	// requests this is the JSON string the caller is expected to
	// `json.Unmarshal` into its target type. For free-form prompts
	// it's the natural-language reply.
	RawText string
	// Provider is the version-stamped provider id round-tripped
	// onto metric labels (e.g. "gemini:gemini-3.1-flash-lite").
	Provider string
	// LatencyMs is the wall-clock provider-call duration. Caller
	// already gets latency via the metrics decorator's histogram —
	// this is here for callers that want to log it themselves.
	LatencyMs int64
}

// ErrorClass categorizes provider failures. Mirrors the TTS seam's
// taxonomy for cross-seam dashboard parity.
type ErrorClass string

const (
	ErrorClassUnknown        ErrorClass = "unknown"
	ErrorClassTimeout        ErrorClass = "timeout"
	ErrorClassConnection     ErrorClass = "connection"
	ErrorClassClientError    ErrorClass = "http_4xx"
	ErrorClassServerError    ErrorClass = "http_5xx"
	ErrorClassReadBody       ErrorClass = "read_body"
	ErrorClassMarshal        ErrorClass = "marshal"
	ErrorClassDecode         ErrorClass = "decode"
	ErrorClassEmptyResponse  ErrorClass = "empty_response"
	ErrorClassMissingPayload ErrorClass = "missing_payload"
)

// Error is the seam's standard provider error.
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

// Provider is the narrow seam interface.
type Provider interface {
	Generate(ctx context.Context, req Request) (*Result, error)
}
