package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func redirectServer(t *testing.T) (srv *httptest.Server, seenPaths *[]string) {
	t.Helper()
	var seen []string
	var mu sync.Mutex
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+"|"+r.Header.Get(InternalAPIKeyHeader))
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/../internal/admin", "/api/v1/x":
			http.Redirect(w, r, "/internal/admin", http.StatusFound)
		case "/slash":
			http.Redirect(w, r, "/slash/", http.StatusTemporaryRedirect)
		case "/open":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestInternalClientDoesNotFollowPathChangingRedirect(t *testing.T) {
	srv, seen := redirectServer(t)
	client := NewInternalClient(time.Second, "secret")
	resp, err := client.Get(srv.URL + "/api/v1/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 returned to the caller", resp.StatusCode)
	}
	for _, s := range *seen {
		if strings.HasPrefix(s, "/internal/admin") {
			t.Fatalf("redirect target was requested with the key: %v", *seen)
		}
	}
}

func TestInternalClientFollowsTrailingSlashRedirect(t *testing.T) {
	srv, seen := redirectServer(t)
	client := NewInternalClient(time.Second, "secret")
	resp, err := client.Post(srv.URL+"/slash", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(*seen) != 2 {
		t.Fatalf("status=%d seen=%v, want the slash hop followed", resp.StatusCode, *seen)
	}
}

func TestNewClientDoesNotFollowRedirectWithCredentials(t *testing.T) {
	srv, seen := redirectServer(t)
	for _, header := range []string{InternalAPIKeyHeader, "Authorization", "X-User-ID"} {
		*seen = nil
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/open", nil)
		req.Header.Set(header, "v")
		resp, err := NewClient(time.Second).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || len(*seen) != 1 {
			t.Fatalf("%s: status=%d seen=%v, want redirect not followed", header, resp.StatusCode, *seen)
		}
	}
}

func TestNewClientFollowsRedirectWithoutCredentials(t *testing.T) {
	srv, seen := redirectServer(t)
	resp, err := NewClient(time.Second).Get(srv.URL + "/open")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(*seen) != 2 {
		t.Fatalf("status=%d seen=%v, want public redirect followed", resp.StatusCode, *seen)
	}
}
