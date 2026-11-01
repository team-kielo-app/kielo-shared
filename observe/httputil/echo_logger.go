package httputil

import (
	"strings"

	"github.com/labstack/echo/v4"
	gommonlog "github.com/labstack/gommon/log"
)

const traceLoggerPrefix = "trace_id="

// withTracedLogger gives the request its own gommon logger whose prefix is "trace_id=<id>", so the ~230
// c.Logger().Infof/Errorf call sites emit lines that contain trace_id=<id> without being edited. It is a real
// gommon logger, not a wrapper, so the "file" and "line" in Echo's default header still name the caller.
//
// Echo clears a context's logger when it recycles the context, and the server-wide echo.Logger is never changed.
// A logger that is not a gommon logger (a service's own) is left alone, as is a context without a trace id.
func withTracedLogger(c echo.Context, traceID string) {
	if traceID == "" {
		return
	}
	base, ok := c.Logger().(*gommonlog.Logger)
	if !ok || strings.HasPrefix(base.Prefix(), traceLoggerPrefix) {
		return
	}
	l := gommonlog.New(traceLoggerPrefix + traceID)
	l.SetOutput(base.Output())
	l.SetLevel(base.Level())
	c.SetLogger(l)
}
