package httputil

import (
	"context"
	"net/http"
	"testing"

	"github.com/team-kielo-app/kielo-shared/observe"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTracingTransport_InjectsHeaders(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	var capturedReq *http.Request
	transport := TracingTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{StatusCode: 200}, nil
	}))

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/test", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	if capturedReq.Header.Get("Traceparent") == "" {
		t.Error("Traceparent header not injected")
	}
	if capturedReq.Header.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id header not injected")
	}
	if capturedReq.Header.Get("X-Client-Trace-Id") == "" {
		t.Error("X-Client-Trace-Id header not injected")
	}
}

func TestTracingTransport_CreatesChildSpan(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	var capturedReq *http.Request
	transport := TracingTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{StatusCode: 200}, nil
	}))

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/test", nil)
	resp, _ := transport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	// Parse the injected traceparent to verify child span
	injectedTP := capturedReq.Header.Get("Traceparent")
	parsed, err := observe.ParseTraceparent(injectedTP)
	if err != nil {
		t.Fatalf("invalid injected traceparent %q: %v", injectedTP, err)
	}

	if parsed.TraceID != tc.TraceID {
		t.Errorf("TraceID changed: got %q, want %q", parsed.TraceID, tc.TraceID)
	}
	if parsed.SpanID == tc.SpanID {
		t.Error("SpanID should be a child span, not the parent's")
	}
}

func TestTracingTransport_NoContext_StillInjects(t *testing.T) {
	transport := TracingTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Traceparent") == "" {
			t.Error("should inject Traceparent even without context trace")
		}
		return &http.Response{StatusCode: 200}, nil
	}))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func TestTracingTransport_DoesNotMutateOriginalHeaders(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)

	transport := TracingTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200}, nil
	}))

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	originalHeaders := req.Header.Clone()

	resp, _ := transport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	// Original request headers should be unchanged (transport clones the request)
	if req.Header.Get("Traceparent") != originalHeaders.Get("Traceparent") {
		t.Error("original request headers were mutated")
	}
}

func TestTracingTransport_NilBase(t *testing.T) {
	// Should not panic — uses http.DefaultTransport
	transport := TracingTransport(nil)
	if transport == nil {
		t.Fatal("should return non-nil transport")
	}
}

func TestInternalAuthTransport_StampsKey(t *testing.T) {
	const key = "s3cret"

	var got string
	tr := InternalAuthTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get(InternalAPIKeyHeader)
		return &http.Response{StatusCode: 200}, nil
	}), key)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	if got != key {
		t.Errorf("X-Internal-API-Key on outbound = %q, want %q", got, key)
	}
}

func TestInternalAuthTransport_PreservesExplicitKey(t *testing.T) {
	const baseline = "baseline-key"
	const override = "override-key"

	var got string
	tr := InternalAuthTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get(InternalAPIKeyHeader)
		return &http.Response{StatusCode: 200}, nil
	}), baseline)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	req.Header.Set(InternalAPIKeyHeader, override)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	if got != override {
		t.Errorf("explicit override discarded: got %q, want %q", got, override)
	}
}

func TestInternalAuthTransport_EmptyKeyIsPassthrough(t *testing.T) {
	var got string
	tr := InternalAuthTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get(InternalAPIKeyHeader)
		return &http.Response{StatusCode: 200}, nil
	}), "")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	resp, _ := tr.RoundTrip(req)
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if got != "" {
		t.Errorf("empty key should be no-op, got %q on outbound", got)
	}
}

func TestNewInternalClient_StampsKeyAndTrace(t *testing.T) {
	const key = "kkk"

	var capturedKey, capturedTraceparent string
	// Build the same composition NewInternalClient uses, but with a
	// terminal roundTripFunc so we don't make a real HTTP call.
	tr := TracingTransport(InternalAuthTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedKey = req.Header.Get(InternalAPIKeyHeader)
		capturedTraceparent = req.Header.Get("Traceparent")
		return &http.Response{StatusCode: 200}, nil
	}), key))

	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	if capturedKey != key {
		t.Errorf("X-Internal-API-Key = %q, want %q", capturedKey, key)
	}
	if capturedTraceparent == "" {
		t.Error("Traceparent header should have been stamped by TracingTransport")
	}
}
