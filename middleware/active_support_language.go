// Package middleware: ActiveSupportLanguage stashes the resolved
// support-language code on the request context so downstream HTTP
// clients (via kielo-shared/observe/httputil.PrepareInternalJSONRequest
// or direct calls to ApplySupportLanguageQuery/Header) can forward the
// signal automatically. Sibling to ActiveLanguage which handles the
// LEARNING language.
//
// Sweep QQQQ canonical: pre-QQQQ Echo services either (a) hand-rolled
// per-handler `c.QueryParam("support_language_code")` + Accept-Language
// chain logic without stashing on ctx, or (b) stashed nothing at all
// and let the upstream service re-resolve from Accept-Language. The
// (a) shape worked for inbound logic but broke for outbound:
// internal HTTP clients had no canonical place to read the resolved
// value, so they dropped the signal on cross-service hops. ActiveSupport
// Language fixes that by mirroring the ActiveLanguage shape: resolve
// once at the gateway boundary, stash on ctx, every downstream client
// reads from the same canonical slot.
package middleware

import (
	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
)

// ActiveSupportLanguageExtractor resolves the support language from
// the request. Use ResolveSupportLanguageStateless (the package-local
// helper) for the default ADR-006 §3.83 chain.
type ActiveSupportLanguageExtractor func(c echo.Context) string

// ActiveSupportLanguage returns Echo middleware that runs the extractor
// on each request and, when it produces a non-empty code, attaches it
// to the request context via httputil.WithSupportLanguage so every
// downstream internal HTTP client picks it up automatically.
//
// Ordering: register **after** the JWT middleware (so claims are on
// echo.Context) and **before** any handler that issues an outbound
// HTTP call. Idempotent when the resolver returns the same value the
// ctx already carries.
//
// Pass nil to use ResolveSupportLanguageStateless (the ADR-006 §3.83
// stateless subset — query → Accept-Language → learning language →
// "en"). The (b) "no profile lookup" variant is the right default for
// every service except BFF + content-service which fetch user profile
// mid-request; those callers should compose the profile-aware shape
// on top of the result and call WithSupportLanguage explicitly.
func ActiveSupportLanguage(extract ActiveSupportLanguageExtractor) echo.MiddlewareFunc {
	if extract == nil {
		extract = ResolveSupportLanguageStateless
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			code := extract(c)
			if code == "" {
				return next(c)
			}
			req := c.Request()
			ctx := db.WithSupportLanguage(req.Context(), code)
			c.SetRequest(req.WithContext(ctx))
			return next(c)
		}
	}
}
