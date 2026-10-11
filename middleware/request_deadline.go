package middleware

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	kerrors "github.com/team-kielo-app/kielo-shared/errors"
)

// RouteDeadline sets the deadline for every path that starts with Prefix.
// Timeout 0 means no deadline for that prefix.
type RouteDeadline struct {
	Prefix  string
	Timeout time.Duration
}

// RequestDeadlineConfig: Default applies to paths no route matches; the
// longest matching Prefix wins. Server-sent event and WebSocket requests are
// never given a deadline.
type RequestDeadlineConfig struct {
	Default time.Duration
	Routes  []RouteDeadline
}

// RequestDeadline bounds how long one request may wait on the database and
// other dependencies. Handlers pass c.Request().Context() down, so when the
// deadline passes every pending query returns and the client gets a 503 it can
// retry, instead of the request holding a Cloud Run slot until the platform's
// 300 s cap. On 2026-10-10 a stalled network path on one user-service
// instance held every request for five minutes.
func RequestDeadline(cfg RequestDeadlineConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			timeout := deadlineFor(cfg, req)
			if timeout <= 0 {
				return next(c)
			}
			ctx, cancel := context.WithTimeout(req.Context(), timeout)
			defer cancel()
			c.SetRequest(req.WithContext(ctx))

			err := next(c)
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return err
			}
			log.Printf("WARN: REQUEST_DEADLINE_EXCEEDED method=%s path=%s timeout=%s", req.Method, c.Path(), timeout)
			if c.Response().Committed {
				return err
			}
			c.Response().Header().Set("Retry-After", "1")
			body := map[string]any{
				"code":    string(kerrors.CodeServiceUnavailable),
				"message": "The service took too long to answer. Please try again.",
			}
			if traceID := traceIDFromContext(req.Context()); traceID != "" {
				body["trace_id"] = traceID
			}
			return c.JSON(http.StatusServiceUnavailable, map[string]any{"message": body["message"], "error": body})
		}
	}
}

func deadlineFor(cfg RequestDeadlineConfig, req *http.Request) time.Duration {
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		return 0
	}
	timeout, matched := cfg.Default, -1
	for _, r := range cfg.Routes {
		if len(r.Prefix) > matched && strings.HasPrefix(req.URL.Path, r.Prefix) {
			timeout, matched = r.Timeout, len(r.Prefix)
		}
	}
	return timeout
}
