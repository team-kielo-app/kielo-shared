package httputil

import (
	"errors"
	"net/http"
	"strings"
	"sync"
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

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

// tunedTransport returns the one [http.Transport] behind every client built
// here. It is a clone of [http.DefaultTransport] with the idle-connection pool
// widened: Go's default MaxIdleConnsPerHost is 2, which starves clients that
// fan heavy concurrent traffic to a few hosts (e.g. a BFF talking to
// user-service, content-service, the learning engine), and every request beyond
// the 2 idle conns/host opens a fresh connection and pays a full TLS handshake.
//
// The clone is made once. A transport owns its connection pool, so a clone per
// [NewClient] gave each of a service's ~25 feature clients its own pool to the
// same few hosts: the same upstream was dialed and TLS-handshaken once per
// client instead of once per process. Timeouts and redirect policy live on the
// [http.Client], and trace and key headers on the wrapping round-trippers, so
// sharing the pool changes none of them. Dial/keep-alive/timeout behavior and
// HTTP/2 negotiation are the defaults'.
func tunedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = http.DefaultTransport.(*http.Transport).Clone()
		sharedTransport.MaxIdleConns = 100
		sharedTransport.MaxIdleConnsPerHost = 32
		sharedTransport.IdleConnTimeout = 90 * time.Second
	})
	return sharedTransport
}

// NewClient returns an [*http.Client] with the given timeout and an outbound
// [TracingTransport] attached so every request propagates W3C traceparent
// headers. Prefer this helper over ad-hoc &http.Client{Timeout: X} so trace
// propagation stays consistent across Kielo services.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     TracingTransport(tunedTransport()),
		CheckRedirect: SafeCheckRedirect,
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
		Timeout:       timeout,
		Transport:     TracingTransport(InternalAuthTransport(tunedTransport(), apiKey)),
		CheckRedirect: redirectPolicy(apiKey != ""),
	}
}

const maxRedirects = 10

var credentialHeaders = []string{InternalAPIKeyHeader, "Authorization", "X-User-ID"}

// SafeCheckRedirect is the redirect policy of every client built here.
//
// Go keeps every header when a redirect stays on the same host, and
// X-Internal-API-Key is not one of the headers it drops on a cross-host hop.
// A front end that answers a dot-segment path with a same-host 302 therefore
// replays the internal key and the caller's JWT against whatever path the
// Location names. A request that carries credentials follows a redirect only
// when it stays on the same scheme and host and changes nothing but a trailing
// slash (the framework "/x" to "/x/" hop); any other hop is returned to the
// caller as the response. A request with no credentials follows up to ten hops
// as net/http does.
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	return redirectPolicy(false)(req, via)
}

// redirectPolicy is SafeCheckRedirect; always marks every request as
// credentialed for clients whose transport adds the internal key itself.
func redirectPolicy(always bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) == 0 || (!always && !carriesCredentials(via[0])) {
			return nil
		}
		prev := via[len(via)-1]
		if req.URL.Scheme != prev.URL.Scheme || !strings.EqualFold(req.URL.Host, prev.URL.Host) {
			return http.ErrUseLastResponse
		}
		if strings.TrimSuffix(req.URL.Path, "/") != strings.TrimSuffix(prev.URL.Path, "/") {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func carriesCredentials(req *http.Request) bool {
	for _, h := range credentialHeaders {
		if req.Header.Get(h) != "" {
			return true
		}
	}
	return false
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
