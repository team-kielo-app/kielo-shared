package httputil

import (
	"bytes"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// AccessLog is Echo's access log (middleware.Logger, the same JSON line) with the request's trace_id after its id:
// the default line carried only X-Request-Id, so a trace id found no access line in any service. Register it after
// [RequestTracing].
func AccessLog() echo.MiddlewareFunc {
	return AccessLogWithConfig(middleware.DefaultLoggerConfig)
}

// AccessLogWithConfig is [AccessLog] over the caller's logger config (a Skipper, another Output).
func AccessLogWithConfig(cfg middleware.LoggerConfig) echo.MiddlewareFunc {
	if !strings.Contains(cfg.Format, "${custom}") {
		cfg.Format = strings.Replace(cfg.Format, `"id":"${id}",`, `"id":"${id}","trace_id":"${custom}",`, 1)
	}
	cfg.CustomTagFunc = func(c echo.Context, buf *bytes.Buffer) (int, error) {
		tc, _ := observe.FromContext(c.Request().Context())
		return buf.WriteString(tc.TraceID)
	}
	return middleware.LoggerWithConfig(cfg)
}
