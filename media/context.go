package media

import (
	"context"
	"net/http"
	"strings"
)

// requestHostKey is the context key under which the original client's
// Host header (or X-Forwarded-Host) is stored. Unexported to guarantee
// callers go through the With/From helpers — no string-typed key clashes.
type requestHostKey struct{}

// WithRequestHost attaches a request-host value to ctx so downstream
// code (repositories, URL composers) can call RequestHostFromContext
// without needing it threaded through every function signature.
//
// Use this at the HTTP handler layer, for example:
//
//	ctx := media.WithRequestHost(c.Request().Context(),
//	    media.EffectiveClientHost(c.Request()))
//
// then pass ctx into repository methods as usual.
func WithRequestHost(ctx context.Context, host string) context.Context {
	host = strings.TrimSpace(host)
	if host == "" {
		return ctx
	}
	return context.WithValue(ctx, requestHostKey{}, host)
}

// RequestHostFromContext returns the request host previously attached
// via WithRequestHost, or "" when none is set. A missing host causes
// URL helpers to return the canonical internal form, which is the
// correct default for internal service-to-service calls.
func RequestHostFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if h, ok := ctx.Value(requestHostKey{}).(string); ok {
		return h
	}
	return ""
}

// EffectiveClientHost returns the request's original client host,
// preferring X-Forwarded-Host (populated by any upstream proxy like
// mobile-bff) over Host (which for a proxied request is the internal
// Docker hostname and would misclassify the caller as internal).
func EffectiveClientHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		// X-Forwarded-Host may be a comma-separated chain; first entry is origin.
		if idx := strings.Index(fwd, ","); idx >= 0 {
			fwd = strings.TrimSpace(fwd[:idx])
		}
		return fwd
	}
	return r.Host
}
