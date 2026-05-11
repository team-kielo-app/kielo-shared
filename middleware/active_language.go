// Package middleware: ActiveLanguage middleware for Echo.
//
// Extracts the active learning language from each request and attaches
// it to the Go context via kielo-shared/db.WithLanguage, so repository
// transactions can issue per-language SET LOCAL search_path. Mirrors
// kielolearn-engine's ActiveLanguageMiddleware on the Python side.
package middleware

import (
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
