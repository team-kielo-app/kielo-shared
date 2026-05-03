// slow_request.go: log a warn-level line when a handler exceeds an
// SLO budget so operators can grep Cloud Logging for outliers without
// pre-querying latency metrics.
//
// Why this exists:
//
// Cloud Run logs every request automatically (path, method, status,
// duration). Filtering for slow requests requires a structured-logging
// query — handy when you know what to look for, useless when you're
// triaging a paging incident at 3am with no prior context. A dedicated
// `[slow] GET /api/v3/feed 1840ms (budget=1000ms)` log line surfaces
// the hot endpoints in the default log feed, sortable + greppable by
// every operator without learning the LogQL/SQL dialect.
//
// The middleware is intentionally:
//   - Per-route opt-in via the threshold being a float per-method/path
//     rule wouldn't scale; one budget per service group is the
//     coarse-but-useful default.
//   - Streaming-safe: it measures from request received to handler
//     return, which for SSE handlers is the entire stream lifetime.
//     Set a generous threshold (5min, 10min) on routers that mount
//     SSE handlers; or apply this middleware only on the non-SSE
//     subgroup.
//   - Skips paths matching common health/probe URLs by default, so a
//     500ms /readyz during DB hiccup doesn't drown the warn channel.

package httputil

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// SlowRequestOptions configures the SlowRequestLogger middleware.
type SlowRequestOptions struct {
	// Threshold is the SLO budget. Requests exceeding this duration
	// emit a warn log line. Zero defaults to 1s — a reasonable budget
	// for sync API calls; SSE/long-poll routes should mount this with
	// a larger value (e.g. 5*time.Minute) or skip them entirely.
	Threshold time.Duration

	// Skip is an optional predicate; returning true bypasses logging
	// for that request. Used to suppress noise from health probes,
	// metrics scrapes, etc. If nil, the default skip rule excludes
	// /health, /readyz, /metrics.
	Skip func(c echo.Context) bool
}

// defaultSlowRequestSkip filters out probe / metric paths whose latency
// is uninteresting in the slow-request feed. /readyz can legitimately
// take 1-2s during a DB ping; we don't want every probe to log.
func defaultSlowRequestSkip(c echo.Context) bool {
	p := c.Request().URL.Path
	switch p {
	case "/health", "/healthz", "/readyz", "/readiness", "/livez", "/metrics":
		return true
	}
	return strings.HasPrefix(p, "/health/")
}

// SlowRequestLogger returns Echo middleware that emits a warn-level
// log line (`[slow] METHOD path durationMs (budget=Xms)`) for any
// request exceeding opts.Threshold. Apply with e.Use() so it covers
// every endpoint; per-route thresholds are unsupported intentionally
// (one budget per service group keeps the log feed digestible).
//
// The log line includes the HTTP status so filterable triage remains
// possible — e.g. `[slow]` AND `status=500` finds slow errors quickly.
func SlowRequestLogger(opts SlowRequestOptions) echo.MiddlewareFunc {
	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = time.Second
	}
	skip := opts.Skip
	if skip == nil {
		skip = defaultSlowRequestSkip
	}
	thresholdMs := threshold.Milliseconds()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skip(c) {
				return next(c)
			}

			start := time.Now()
			err := next(c)
			elapsed := time.Since(start)
			if elapsed < threshold {
				return err
			}

			req := c.Request()
			res := c.Response()
			status := res.Status
			if status == 0 {
				status = http.StatusOK
			}
			log.Printf(
				"[slow] %s %s durationMs=%d budget=%dms status=%d",
				req.Method,
				req.URL.Path,
				elapsed.Milliseconds(),
				thresholdMs,
				status,
			)
			return err
		}
	}
}
