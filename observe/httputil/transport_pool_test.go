package httputil

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var conns atomic.Int32
	var lastKey atomic.Value
	lastKey.Store("")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastKey.Store(r.Header.Get(InternalAPIKeyHeader))
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &conns, &lastKey
}

func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func TestClientsShareOneConnectionPool(t *testing.T) {
	srv, conns, _ := countingServer(t)
	clients := []*http.Client{
		NewClient(time.Second),
		NewClient(15 * time.Second),
		NewInternalClient(time.Second, "key-a"),
		NewInternalClient(3*time.Second, "key-b"),
		NewInternalClient(time.Second, ""),
	}

	const rounds = 10
	for i := 0; i < rounds; i++ {
		for _, client := range clients {
			get(t, client, srv.URL)
		}
	}

	if got := conns.Load(); got != 1 {
		t.Fatalf("server accepted %d connections for %d calls across %d clients, want 1", got, rounds*len(clients), len(clients))
	}
}

func TestSharedPoolKeepsPerClientTimeoutAndKey(t *testing.T) {
	srv, _, lastKey := countingServer(t)

	get(t, NewInternalClient(time.Second, "key-a"), srv.URL)
	if got := lastKey.Load(); got != "key-a" {
		t.Fatalf("internal client sent key %q, want key-a", got)
	}
	get(t, NewClient(time.Second), srv.URL)
	if got := lastKey.Load(); got != "" {
		t.Fatalf("plain client sent key %q, want none", got)
	}

	if NewClient(time.Second).Timeout == NewClient(9*time.Second).Timeout {
		t.Fatal("clients on the shared pool lost their own timeout")
	}
}

func TestTunedTransportIsOneWidenedTransport(t *testing.T) {
	first, second := tunedTransport(), tunedTransport()
	if first != second {
		t.Fatal("tunedTransport returned a different transport on the second call")
	}
	if first == http.DefaultTransport {
		t.Fatal("tunedTransport must not be http.DefaultTransport itself")
	}
	if first.MaxIdleConnsPerHost != 32 || first.MaxIdleConns != 100 || first.IdleConnTimeout != 90*time.Second {
		t.Fatalf("pool limits = %d/%d/%s, want 100/32/90s", first.MaxIdleConns, first.MaxIdleConnsPerHost, first.IdleConnTimeout)
	}
	if !first.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2 negotiation was lost from the cloned default transport")
	}
}
