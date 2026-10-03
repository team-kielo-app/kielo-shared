package middleware

import (
	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

// TimezoneOffset stamps the caller's X-Timezone-Offset-Minutes (legacy alias
// X-Timezone-Offset) onto the request context so downstream outbound calls
// forward it and events.HTTPEmitter stamps context.tz_offset_minutes on the
// envelopes it emits. A missing or invalid header leaves the context untouched.
func TimezoneOffset() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := c.Request().Header.Get(timeutil.TimezoneOffsetHeader)
			if raw == "" {
				raw = c.Request().Header.Get("X-Timezone-Offset")
			}
			if offset, ok := timeutil.ParseTimezoneOffsetMinutes(raw); ok {
				c.SetRequest(c.Request().WithContext(timeutil.WithTimezoneOffsetMinutes(c.Request().Context(), offset)))
			}
			return next(c)
		}
	}
}
