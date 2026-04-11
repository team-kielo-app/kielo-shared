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
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
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
	_, _ = transport.RoundTrip(req)

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
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
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

	_, _ = transport.RoundTrip(req)

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
