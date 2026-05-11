package httputil

import (
	"net/http"
	"time"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// TracingTransport wraps an [http.RoundTripper] to automatically inject trace
// headers on every outbound HTTP request. It creates a child span for each
// outgoing call, preserving the trace_id from the request context.
//
// If base is nil, [http.DefaultTransport] is used.
//
// Usage:
//
//	client := &http.Client{
//	    Transport: httputil.TracingTransport(nil),
//	    Timeout:   5 * time.Second,
//	}
func TracingTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &tracingTransport{base: base}
}

// InternalAuthTransport wraps base so every outbound request carries the
// Kielo internal API key header (X-Internal-API-Key) — but ONLY when the
// caller didn't already set it. The "didn't already set it" rule lets
// per-call overrides (e.g. an admin endpoint that needs to talk to a peer
// service with a privileged key) still work without the transport
// silently overwriting.
//
// Use this when constructing an http.Client that exclusively talks to
// Kielo internal services. For mixed-traffic clients prefer
// PrepareInternalJSONRequest which sets the header per-request.
//
// If apiKey is empty the transport is a no-op pass-through (handy for
// local dev with no key configured).
//
// Combine with TracingTransport for the full internal-call stack:
//
//	client := &http.Client{
//	    Timeout:   10 * time.Second,
//	    Transport: TracingTransport(InternalAuthTransport(nil, key)),
//	}
//
// Or use [NewInternalClient] which does both.
func InternalAuthTransport(base http.RoundTripper, apiKey string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if apiKey == "" {
		return base
	}
	return &internalAuthTransport{base: base, apiKey: apiKey}
}

// NewClient returns an [*http.Client] with the given timeout and an outbound
// [TracingTransport] attached so every request propagates W3C traceparent
// headers. Prefer this helper over ad-hoc &http.Client{Timeout: X} so trace
// propagation stays consistent across Kielo services.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: TracingTransport(nil),
	}
}

// NewInternalClient returns an [*http.Client] for service-to-service
// calls between Kielo services. Every request automatically carries:
//
//   - W3C Traceparent / X-Request-Id / X-Client-Trace-Id (via TracingTransport)
//   - X-Internal-API-Key set to apiKey (via InternalAuthTransport)
//
// Headers explicitly set by the caller are preserved — both transports
// fall back to set-if-missing for trace / set-if-missing for the key.
//
// Prefer this over &http.Client{Timeout: X} whenever the call target is
// another Kielo service. Pair with PrepareInternalJSONRequest when the
// request body is JSON; for non-JSON bodies (multipart, streams) build
// the request manually and fire it through this client.
//
// If apiKey is empty the client behaves the same as [NewClient]; the
// internal-auth layer becomes a pass-through.
func NewInternalClient(timeout time.Duration, apiKey string) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: TracingTransport(InternalAuthTransport(nil, apiKey)),
	}
}

type tracingTransport struct {
	base http.RoundTripper
}

func (t *tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tc, ok := observe.FromContext(req.Context())
	if !ok {
		// No trace in context — generate one so downstream still gets headers
		tc = observe.New()
	}

	child := observe.ChildSpan(tc)

	// Clone headers to avoid mutating the original request
	req = req.Clone(req.Context())
	observe.InjectHeaders(req.Header, child)

	return t.base.RoundTrip(req)
}

type internalAuthTransport struct {
	base   http.RoundTripper
	apiKey string
}

func (t *internalAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Don't mutate the caller's request — TracingTransport already clones
	// when wrapping, but other consumers may not; defend ourselves.
	if req.Header.Get(InternalAPIKeyHeader) != "" {
		return t.base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	req.Header.Set(InternalAPIKeyHeader, t.apiKey)
	return t.base.RoundTrip(req)
}
