package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	kerrors "github.com/team-kielo-app/kielo-shared/errors"
)

// WriteRateLimitDenied writes the canonical 429 body for a transport-level rate
// limiter, plus the Retry-After header.
//
// Exists because every service was hand-rolling this and getting it wrong the
// same way: `c.JSON(429, map[string]string{"message": ...})`. That body carries no
// `error.code`, and the mobile client classifies limit responses by code —
// anything it cannot classify renders as "Something went wrong. Please try
// again.", which is the worst available copy here, because a rate limit is
// temporary and self-resolving and the user is told neither of those things.
// Found in kielo-mobile-bff (feedback limiter) and kielo-content-service (both
// its default and strict limiters, IP-keyed in front of the KieloTV feed).
//
// The code is deliberately RATE_LIMITED and never FEATURE_LIMIT_REACHED: a quota
// is fixed by upgrading, a rate limit is fixed by waiting, and offering an
// upgrade that changes nothing is worse than saying nothing. Callers enforcing a
// per-plan quota must build their own envelope with the quota code and its
// remaining/limit/tier fields.
//
// retryAfter is rounded up to whole seconds, per RFC 9110 §10.2.3; a non-positive
// value omits both the header and the body field rather than advertising "retry
// immediately", which would invite a hot loop.
func WriteRateLimitDenied(c echo.Context, message string, retryAfter time.Duration) error {
	if message == "" {
		message = "Too many requests. Please try again later."
	}

	errorBody := map[string]any{
		"code":    string(kerrors.CodeRateLimited),
		"message": message,
	}

	seconds := int(retryAfter.Round(time.Second).Seconds())
	if retryAfter > 0 && seconds == 0 {
		seconds = 1 // sub-second windows still deserve a truthful "wait a moment"
	}
	if seconds > 0 {
		errorBody["retry_after_seconds"] = seconds
		c.Response().Header().Set("Retry-After", strconv.Itoa(seconds))
	}

	if traceID := traceIDFromContext(c.Request().Context()); traceID != "" {
		errorBody["trace_id"] = traceID
	}

	return c.JSON(http.StatusTooManyRequests, map[string]any{
		"message": message,
		"error":   errorBody,
	})
}
