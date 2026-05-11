// cors_default.go: canonical CORS baseline shared by every Kielo Echo
// service.
//
// Before this helper landed, each service copy-pasted CORSWithConfig
// with subtly different AllowMethods and AllowHeaders. The fan-out
// caused two recurring bugs:
//
//  1. A new canonical header (e.g. X-Kielo-Learning-Language during the
//     two-axis language migration) was added in 3 services but missed
//     in 3 others, surfacing as silent CORS preflight failures only on
//     the affected endpoints.
//  2. AllowMethods drifted (comms had no OPTIONS, auth had no PATCH,
//     etc.) so preflight responses were inconsistent across the
//     surface that the same mobile/admin client talks to.
//
// DefaultCORSConfig fixes both by returning a single canonical
// echomiddleware.CORSConfig. Services that need fewer methods narrow
// via CORSOptions.Methods. AllowHeaders is mandatory and may only be
// EXTENDED, never shrunk — the baseline is what mobile-app and
// admin-ui stamp unconditionally.
//
// Per ADR-006 §10 (Request Handling Standard).

package middleware

import (
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// DefaultCORSAllowMethods is the canonical method set: a service that
// exposes any v3 surface should accept the full REST verb range plus
// OPTIONS for preflight. Services that genuinely don't expose a verb
// (auth-service is read/write-only, no PATCH/DELETE) MAY narrow via
// CORSOptions.Methods.
var DefaultCORSAllowMethods = []string{
	echo.GET,
	echo.POST,
	echo.PUT,
	echo.PATCH,
	echo.DELETE,
	echo.OPTIONS,
}

// DefaultCORSAllowHeaders is the canonical request header allow-list.
// Every Kielo service MUST accept this set so the mobile-app /
// admin-ui can send headers unconditionally without having to learn
// which header each backend supports.
//
// Header inventory:
//   - Origin, Content-Type, Accept, Authorization: HTTP/CORS baseline.
//   - X-Requested-With: legacy XHR sentinel; kept for back-compat with
//     older admin tooling.
//   - X-Internal-API-Key: service-to-service shared secret (ADR-006 §2).
//   - X-API-Key: admin-ui's admin shared secret (distinct from internal
//     API key — see ADR-006 §2 note).
//   - X-Device-Token: mobile-app per-install token.
//   - X-Kielo-Learning-Language: canonical learning-language header
//     (ADR-001).
//   - X-Learning-Language: legacy mobile equivalent of above; accepted
//     during the deprecation window (ADR-006 §3 / removal M+6).
//   - X-Client-Trace-Id, X-Request-Id, Traceparent: trace correlation
//     (ADR-006 §1). Traceparent is canonical, the other two stay
//     accepted for backward compat.
//   - X-Timezone-Offset-Minutes: mobile-app local-time hint for
//     scheduling features.
//   - Accept-Language: BCP-47 support-language fallback (ADR-006 §3).
//   - X-Idempotency-Key, Idempotency-Key: server-side dedupe key
//     (ADR-003 + ADR-006 §11). Both spellings are accepted; the latter
//     is the IETF draft canonical.
//   - X-User-ID: media-upload internal handshake; kept here so the
//     admin UI doesn't need a separate CORS config for that one
//     service.
var DefaultCORSAllowHeaders = []string{
	echo.HeaderOrigin,
	echo.HeaderContentType,
	echo.HeaderAccept,
	echo.HeaderAuthorization,
	"Accept-Language",
	"X-Requested-With",
	"X-Internal-API-Key",
	"X-API-Key",
	"X-Device-Token",
	"X-Kielo-Learning-Language",
	"X-Learning-Language",
	"X-Client-Trace-Id",
	"X-Request-Id",
	observe.HeaderTraceparent,
	"X-Timezone-Offset-Minutes",
	"X-Idempotency-Key",
	"Idempotency-Key",
	"X-User-ID",
}

// DefaultCORSExposeHeaders are the response headers a CORS-restricted
// client (admin-ui in a browser) is allowed to READ from
// XHR/fetch responses. Without these the browser hides them.
//
//   - X-Request-Id, Traceparent: clients log these for support tickets.
//   - Sunset, Deprecation: RFC 8594 / draft IETF deprecation
//     signaling so the admin UI can warn when it's calling a
//     deprecated endpoint.
var DefaultCORSExposeHeaders = []string{
	"X-Request-Id",
	observe.HeaderTraceparent,
	"Sunset",
	"Deprecation",
}

// CORSOptions narrows the canonical default in the few legitimate
// cases where a service needs a tighter method set or extra headers
// beyond the baseline.
type CORSOptions struct {
	// Methods overrides DefaultCORSAllowMethods. nil = use the
	// canonical set. Services should narrow this only when they
	// genuinely don't serve a verb (auth-service has no PATCH).
	Methods []string

	// ExtraAllowHeaders are appended to DefaultCORSAllowHeaders.
	// Use for service-specific headers (e.g. an upload service that
	// accepts a one-off "X-Upload-Token"). The baseline is always
	// included — extension only, no replacement.
	ExtraAllowHeaders []string

	// ExtraExposeHeaders are appended to DefaultCORSExposeHeaders.
	ExtraExposeHeaders []string

	// AllowCredentials defaults to true. Set false explicitly only
	// for fully public endpoints (no auth cookie / no Authorization
	// header dependency).
	AllowCredentials *bool

	// MaxAge is the preflight cache TTL in seconds. Defaults to 300
	// (5 minutes). 0 means caller wants the default; use a negative
	// number to force no caching.
	MaxAge int
}

// DefaultCORSConfig returns the canonical echomiddleware.CORSConfig
// for a Kielo Echo service.
//
// origins MUST be supplied by the caller — usually via
// `CORSAllowedOrigins(serviceSpecificFallback)`. Passing nil/empty
// would make Echo's CORS middleware silently allow any origin, which
// is the footgun this helper exists to prevent.
//
// Usage:
//
//	e.Use(echomiddleware.CORSWithConfig(sharedmiddleware.DefaultCORSConfig(
//	    sharedmiddleware.CORSAllowedOrigins("https://admin.kielo.app"),
//	    sharedmiddleware.CORSOptions{},
//	)))
func DefaultCORSConfig(origins []string, opts CORSOptions) echomiddleware.CORSConfig {
	methods := opts.Methods
	if methods == nil {
		methods = append(methods, DefaultCORSAllowMethods...)
	}

	headers := make([]string, 0, len(DefaultCORSAllowHeaders)+len(opts.ExtraAllowHeaders))
	headers = append(headers, DefaultCORSAllowHeaders...)
	headers = append(headers, opts.ExtraAllowHeaders...)

	expose := make([]string, 0, len(DefaultCORSExposeHeaders)+len(opts.ExtraExposeHeaders))
	expose = append(expose, DefaultCORSExposeHeaders...)
	expose = append(expose, opts.ExtraExposeHeaders...)

	allowCreds := true
	if opts.AllowCredentials != nil {
		allowCreds = *opts.AllowCredentials
	}

	maxAge := opts.MaxAge
	if maxAge == 0 {
		maxAge = 300
	}
	if maxAge < 0 {
		maxAge = 0
	}

	return echomiddleware.CORSConfig{
		AllowOrigins:     origins,
		AllowMethods:     methods,
		AllowHeaders:     headers,
		ExposeHeaders:    expose,
		AllowCredentials: allowCreds,
		MaxAge:           maxAge,
	}
}
