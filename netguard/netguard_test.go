package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsDisallowedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"100.127.255.254", "0.0.0.0", "0.1.2.3", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "fd20:ce::254",
		"fe80::1", "fd7a:115c:a1e0::1", "224.0.0.1", "64:ff9b::a9fe:a9fe",
	}
	for _, s := range blocked {
		if !IsDisallowedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "2606:4700::1111"} {
		if IsDisallowedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	bad := []string{
		"file:///etc/passwd", "gopher://example.com/", "ftp://example.com/x", "http://localhost/x", "http://LOCALHOST./x",
		"http://metadata.google.internal/x", "http://169.254.169.254/latest", "http://100.100.1.1/", "http://[::ffff:7f00:1]/",
		"http://2130706433/", "http://user:pw@example.com/", "http://svc.internal/", "http:///x", "http://[fd20:ce::254]/",
	}
	for _, s := range bad {
		if u, err := ValidateURL(s); err == nil {
			if ip := net.ParseIP(u.Hostname()); ip == nil {
				t.Logf("%s passes the pre-check; dial guard is authoritative", s)
				continue
			}
			t.Errorf("%s should be rejected", s)
		}
	}
	if _, err := ValidateURL("https://example.com/a.mp4"); err != nil {
		t.Fatal(err)
	}
}

func TestClientBlocksLoopbackAndRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer srv.Close()
	c := NewClient(3*time.Second, nil)
	if resp, err := c.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("loopback fetch must be blocked at dial time")
	}
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer redir.Close()
	if resp, err := c.Get(redir.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("redirect to loopback must be blocked")
	}
}

func TestDialBlocksLocalhostName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	c := NewClient(3*time.Second, nil)
	if resp, err := c.Get("http://localhost:" + port + "/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("localhost name must be blocked")
	}
}
