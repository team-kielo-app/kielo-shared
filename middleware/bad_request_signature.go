package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// BadRequestSignature fast-rejects HTTP requests whose path contains
// known client-bug signatures, before the request reaches auth, JWT
// validation, rate limit, or any handler logic.
//
// Currently the only signature is the literal substring "[object" —
// what JavaScript produces when a non-string value is coerced into a
// URL template (e.g. `${someObject}` instead of `${someObject.id}` →
// "[object Object]"). The buggy Android cohort observed in production
// logs (2026-05-17) emits ~10 req/s of GET /api/v3/conversations/
// scenarios/[object%20Object] paths that would otherwise pass through
// the full middleware chain before 404-ing in the router.
//
// The match is case-sensitive and conservative: legitimate URLs do
// not contain "[object" since `[` is a reserved character in path
// segments. The Go net/url package decodes %5B → [ in URL.Path before
// this middleware runs, so both URL-encoded and decoded forms are
// caught.
//
// Returns the canonical error envelope so client telemetry can
// distinguish this signature from other 400s.
func BadRequestSignature() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if strings.Contains(c.Request().URL.Path, "[object") {
				return APIError(c, http.StatusBadRequest,
					"BAD_REQUEST_SIGNATURE",
					"Request URL contains a client-side serialization error. "+
						"Check that path parameters are strings, not objects.",
					nil)
			}
			return next(c)
		}
	}
}
