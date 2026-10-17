package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxRedirects = 5

var ErrBlocked = errors.New("netguard: destination not allowed")

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

func IsDisallowedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func isBlockedHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "metadata.google.internal" ||
		h == "metadata" || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".local")
}

func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("url scheme must be http or https")
	}
	if u.User != nil {
		return nil, fmt.Errorf("url credentials not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("url missing host")
	}
	if isBlockedHostname(host) {
		return nil, fmt.Errorf("host not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && IsDisallowedIP(ip) {
		return nil, fmt.Errorf("host resolves to a disallowed address")
	}
	return u, nil
}

func DialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%w: no addresses for %s", ErrBlocked, host)
		}
		for _, ip := range ips {
			if IsDisallowedIP(ip.IP) {
				return nil, fmt.Errorf("%w: %s", ErrBlocked, ip.IP)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func NewClient(timeout time.Duration, wrap func(http.RoundTripper) http.RoundTripper) *http.Client {
	var rt http.RoundTripper = &http.Transport{
		DialContext:         DialContext(&net.Dialer{Timeout: 10 * time.Second}),
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if wrap != nil {
		rt = wrap(rt)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: rt,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects")
			}
			_, err := ValidateURL(r.URL.String())
			return err
		},
	}
}
