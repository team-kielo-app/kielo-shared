// Package httputil provides Echo middleware and HTTP transport wrappers for
// automatic trace context propagation.
package httputil

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/observe"
)

const echoTraceContextKey = "trace_context"

// RequestTracing returns Echo middleware that extracts or creates a
// [observe.TraceContext] for each request, stores it in both the stdlib context
// (for downstream service/repo layers) and Echo context (for handlers), and
// sets trace response headers.
func RequestTracing() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			incoming := observe.FromHeaders(c.Request().Header)

			// Create a child span for this service hop
			tc := observe.ChildSpan(incoming)

			// Store in stdlib context (flows to service layers, HTTP clients)
			ctx := observe.WithContext(c.Request().Context(), tc)
			c.SetRequest(c.Request().WithContext(ctx))

			// Store in Echo context (accessible via c.Get)
			c.Set(echoTraceContextKey, tc)

			// Set response headers
			observe.InjectHeaders(c.Response().Header(), tc)

			return next(c)
		}
	}
}

// TraceFromEcho extracts the TraceContext stored by [RequestTracing] from an
// Echo context. Returns zero value and false if not present.
func TraceFromEcho(c echo.Context) (observe.TraceContext, bool) {
	tc, ok := c.Get(echoTraceContextKey).(observe.TraceContext)
	return tc, ok
}

// RequestTracingStdlib wraps a stdlib http.Handler with the same trace
// context plumbing as [RequestTracing]. Use this for services that don't
// run on Echo (raw http.Server, custom routers).
func RequestTracingStdlib(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		incoming := observe.FromHeaders(r.Header)
		tc := observe.ChildSpan(incoming)
		ctx := observe.WithContext(r.Context(), tc)
		observe.InjectHeaders(w.Header(), tc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestTracingChi is the chi-flavored middleware. chi accepts a
// `func(http.Handler) http.Handler` so this is a thin alias around
// [RequestTracingStdlib].
func RequestTracingChi(next http.Handler) http.Handler {
	return RequestTracingStdlib(next)
}

// RequestLogger returns Echo middleware that logs each request with structured
// fields including trace context. It should be registered after [RequestTracing].
//
// Log levels by status code:
//   - 5xx: Error
//   - 4xx: Warn
//   - 2xx/3xx: Info
func RequestLogger(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			err := next(c)
			if err != nil {
				c.Error(err)
			}

			duration := time.Since(start)
			status := c.Response().Status
			ctx := c.Request().Context()

			attrs := []slog.Attr{
				slog.String("method", c.Request().Method),
				slog.String("path", c.Request().URL.Path),
				slog.String("route", c.Path()),
				slog.Int("status", status),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
				slog.Int64("bytes_out", c.Response().Size),
				slog.String("remote_addr", c.RealIP()),
			}

			// Add user_id if available from auth middleware
			if uid, ok := c.Get("userID").(string); ok && uid != "" {
				attrs = append(attrs, slog.String("user_id", uid))
			}

			if lang, ok := db.LanguageFromContext(ctx); ok && lang != "" {
				attrs = append(attrs, slog.String("learning_language_code", lang))
			}

			level := slog.LevelInfo
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			}

			// Use InfoContext so the trace handler can extract trace fields
			record := slog.NewRecord(time.Now(), level, "request", 0)
			record.AddAttrs(attrs...)
			_ = logger.Handler().Handle(ctx, record)

			return nil
		}
	}
}
