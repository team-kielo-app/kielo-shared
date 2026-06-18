// Package middleware: ResolveSupportLanguage canonicalizes the
// per-ADR-006 §3 resolution chain for the *support* language (the UI
// translation locale), which is distinct from the *learning* language
// (the language the user is studying, handled by ActiveLanguage).
//
// Every Go service that exposes hydrated localized payloads to clients
// previously hand-rolled `c.QueryParam("support_language_code")` and
// stopped there, silently ignoring the `Accept-Language` header and
// the learning-language fallback that ADR-006 §3.83 mandates:
//
//	explicit query/header → user profile → Accept-Language (BCP47)
//	→ fallback to learning language → "en"
//
// This helper consolidates the first, third, and last steps (the
// "stateless" subset). The profile-fetch step is a service-specific
// concern (only BFF + content-service hydrate profile mid-request) so
// callers compose it on top of the result here.
package middleware

import (
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

const (
	// SupportLanguageQueryParam is the canonical query-string parameter
	// for the UI/support language across all v3 endpoints.
	SupportLanguageQueryParam = "support_language_code"

	// AcceptLanguageHeader is the standard HTTP content-negotiation
	// header. Clients that follow BCP47 (every mainstream browser,
	// most HTTP libraries, react-native fetch) populate it
	// automatically; ignoring it for support-language resolution
	// means we serve `en` to a user whose browser explicitly asked
	// for `vi` or `fi`.
	AcceptLanguageHeader = "Accept-Language"
)

// ResolveSupportLanguageStateless implements the stateless portion of
// the ADR-006 §3.83 chain:
//
//  1. ?support_language_code= query parameter (explicit per-call override)
//  2. Accept-Language header (BCP47 — first supported match wins)
//  3. Learning language from request context (set by ActiveLanguage),
//     coerced through the support-locale supported set
//  4. locale.TierASupportLocale ("en")
//
// The profile lookup (step 3 in the spec) is omitted because it
// requires an HTTP call back to kielo-user-service, which the shared
// package cannot perform without pulling in service-specific
// dependencies. Callers that need the profile step should:
//
//	stateless := ResolveSupportLanguageStateless(c)
//	if isExplicit(c) { return stateless }
//	if profile := h.fetchProfile(...); profile != "" { return profile }
//	return stateless
//
// Returns a non-empty BCP47 base code (e.g. "en", "fi", "vi"). Falls
// through to TierASupportLocale rather than returning "" to keep
// downstream code free of nil-check branches.
func ResolveSupportLanguageStateless(c echo.Context) string {
	if v := strings.TrimSpace(c.QueryParam(SupportLanguageQueryParam)); v != "" {
		if code := locale.BaseLocale(locale.NormalizeAcceptLanguage(v)); code != "" && locale.IsSupportedSupportLanguage(code) {
			return code
		}
	}
	if v := strings.TrimSpace(c.Request().Header.Get(AcceptLanguageHeader)); v != "" {
		if code := locale.BaseLocale(locale.NormalizeAcceptLanguage(v)); code != "" && locale.IsSupportedSupportLanguage(code) {
			return code
		}
	}
	if learning, ok := db.LanguageFromContext(c.Request().Context()); ok && learning != "" {
		if code := locale.BaseLocale(locale.NormalizeAcceptLanguage(learning)); code != "" && locale.IsSupportedSupportLanguage(code) {
			return code
		}
	}
	return locale.TierASupportLocale
}
