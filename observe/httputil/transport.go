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
