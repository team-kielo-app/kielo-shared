// Package middleware: ActiveLanguage middleware for Echo.
//
// Extracts the active learning language from each request and attaches
// it to the Go context via kielo-shared/db.WithLanguage, so repository
// transactions can issue per-language SET LOCAL search_path. Mirrors
// kielolearn-engine's ActiveLanguageMiddleware on the Python side.
package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

const (
	// ActiveLanguageQueryParam is the canonical query-string parameter
	// that carries the active learning language across cross-service
	// HTTP hops. Stamped by sharedhttputil.ApplyActiveLanguageQuery on
	// every internal outbound call.
	ActiveLanguageQueryParam = "learning_language_code"

	// ActiveLanguageHeader is the canonical service-to-service header
	// per ADR-006 §3. Stamped on internal outbound HTTP calls by the
	// shared http client; preferred over the JWT claim because it
	// reflects the caller's explicit intent for this request rather
	// than the user's profile default.
	ActiveLanguageHeader = "X-Kielo-Learning-Language"

	// LegacyActiveLanguageHeader is the pre-ADR-006 name. Kept for one
	// migration window so older mobile clients and any straggling
	// internal callers continue to work; remove after M+12.
	LegacyActiveLanguageHeader = "X-Learning-Language"

	// JWTClaimKey is the standard claim name set by kielo-auth-service
	// when issuing tokens. The JWT middleware on the receiving service
	// is responsible for decoding the token and stashing claims on
	// echo.Context — this middleware reads them back out.
	JWTClaimKey = "learning_language_code"
)

// ActiveLanguageExtractor is the resolution strategy. Returns the
// language code (validated by db.ValidateLanguageIdent) or "" if no
// source matched. Customizable so individual services can plug in their
// own JWT claim layout, profile lookup, etc.
type ActiveLanguageExtractor func(c echo.Context) string

// DefaultExtractor resolves in priority order per ADR-006 §3:
//
//  1. ?learning_language_code query parameter (explicit per-call override)
//  2. X-Kielo-Learning-Language header (canonical service-to-service)
//  3. X-Learning-Language header (legacy; sunset M+12)
//  4. echo.Context.Get(JWTClaimKey) (user's profile default)
//
// Bad values (failing db.ValidateLanguageIdent) are dropped silently;
// the chain continues. The middleware itself never short-circuits the
// request — a missing language just means no per-language scope, in
// which case repository code returns ErrNoActiveLanguage when it tries
// to open a per-language transaction.
func DefaultExtractor(c echo.Context) string {
	if v := strings.TrimSpace(c.QueryParam(ActiveLanguageQueryParam)); v != "" {
		if lang := locale.NormalizeSupportedLearningLanguageCode(v); lang != "" {
			return lang
		}
	}
	if v := strings.TrimSpace(c.Request().Header.Get(ActiveLanguageHeader)); v != "" {
		if lang := locale.NormalizeSupportedLearningLanguageCode(v); lang != "" {
			return lang
		}
	}
	if v := strings.TrimSpace(c.Request().Header.Get(LegacyActiveLanguageHeader)); v != "" {
		if lang := locale.NormalizeSupportedLearningLanguageCode(v); lang != "" {
			return lang
		}
	}
	if claim, ok := c.Get(JWTClaimKey).(string); ok {
		if v := strings.TrimSpace(claim); v != "" {
			if lang := locale.NormalizeSupportedLearningLanguageCode(v); lang != "" {
				return lang
			}
		}
	}
	return ""
}

// ActiveLanguage returns Echo middleware that runs the extractor on each
// request and, when it produces a valid language, attaches it to the
// request context via db.WithLanguage. Pass nil to use DefaultExtractor.
//
// Ordering: register **after** the JWT middleware (so claims are on
// echo.Context) and **before** any handler that opens a DB transaction.
func ActiveLanguage(extract ActiveLanguageExtractor) echo.MiddlewareFunc {
	if extract == nil {
		extract = DefaultExtractor
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			lang := extract(c)
			if lang == "" {
				return next(c)
			}
			req := c.Request()
			if db.ValidateLearningLanguageIdent(lang) != nil {
				return next(c)
			}
			ctx := db.WithLanguage(req.Context(), lang)
			c.SetRequest(req.WithContext(ctx))
			return next(c)
		}
	}
}

// RequireActiveLanguageOptions configures RequireActiveLanguage.
type RequireActiveLanguageOptions struct {
	// AllowInternalAPIKeyBypass: when true (default), requests with
	// X-Internal-API-Key are allowed through without a language. Set
	// to false on route groups that ALREADY require the internal API
	// key as their auth mechanism — in that case the carveout would
	// degenerate to 100%-bypass and the gate would be useless.
	AllowInternalAPIKeyBypass bool
}

// RequireActiveLanguage returns Echo middleware that 400s a request when
// no valid learning language is resolved from the extractor chain. Use
// this on route groups that touch per-language tables (klearn_<lang>,
// cms_<lang>); without it the search_path resolver silently falls back
// to the legacy schema and the request returns wrong (or empty) data.
//
// Phase 10C: the kielolearn-engine Python middleware has its own strict
// dependency (require_active_learning_language); this Go variant
// provides the same guarantee for Echo-based services (kielo-cms,
// kielo-user-service, etc.) at the route-group level rather than per-
// handler.
//
// Ordering: register **after** ActiveLanguage (which populates ctx) on
// the same route group. The extractor passed here MUST be the same one
// passed to ActiveLanguage so the resolution chain is consistent.
//
// Default behavior includes the admin / internal carve-out: callers
// can bypass this gate by setting X-Internal-API-Key. Admin tools that
// legitimately fan out across languages (cross-language listings, audit
// scripts, etc.) opt in via the header. End-user requests don't carry
// the header so the gate still applies. Use RequireActiveLanguageWithOptions
// to disable the carveout on route groups already authenticated by the
// internal API key.
func RequireActiveLanguage(extract ActiveLanguageExtractor) echo.MiddlewareFunc {
	return RequireActiveLanguageWithOptions(extract, RequireActiveLanguageOptions{
		AllowInternalAPIKeyBypass: true,
	})
}

// RequireActiveLanguageWithOptions is RequireActiveLanguage with explicit
// option control. Use this when the route group's auth mechanism
// already gates on the internal API key, where AllowInternalAPIKeyBypass=false
// is the correct setting (otherwise the gate becomes a 100%-bypass).
func RequireActiveLanguageWithOptions(
	extract ActiveLanguageExtractor,
	opts RequireActiveLanguageOptions,
) echo.MiddlewareFunc {
	if extract == nil {
		extract = DefaultExtractor
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, ok := db.LanguageFromContext(c.Request().Context()); ok {
				// ActiveLanguage middleware already set a valid language.
				return next(c)
			}
			if opts.AllowInternalAPIKeyBypass &&
				c.Request().Header.Get("X-Internal-API-Key") != "" {
				return next(c)
			}
			// Re-run the extractor to surface WHY no language was
			// attached (helps with audit-log readability — the response
			// body identifies the misshaped request without forcing the
			// caller to grep logs).
			raw := extract(c)
			return echo.NewHTTPError(
				http.StatusBadRequest,
				"learning_language_code is required for this route; "+
					"supply via X-Kielo-Learning-Language header, "+
					"learning_language_code query param, or JWT claim "+
					"(extractor produced: "+raw+")",
			)
		}
	}
}
