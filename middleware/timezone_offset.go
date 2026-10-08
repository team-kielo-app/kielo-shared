package middleware

import (
	"time"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

// TimezoneOffset stamps the caller's X-Timezone-Offset-Minutes (legacy alias
// X-Timezone-Offset) and IANA X-Timezone onto the request context so
// downstream outbound calls forward them and events.HTTPEmitter stamps
// context.tz_offset_minutes on the envelopes it emits. With only a zone, the
// offset is derived from it. Missing or invalid headers leave the context
// untouched.
func TimezoneOffset() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := c.Request().Header.Get(timeutil.TimezoneOffsetHeader)
			if raw == "" {
				raw = c.Request().Header.Get("X-Timezone-Offset")
			}
			ctx := c.Request().Context()
			zone, hasZone := timeutil.ParseTimezoneName(c.Request().Header.Get(timeutil.TimezoneHeader))
			if hasZone {
				ctx = timeutil.WithTimezoneName(ctx, zone)
			}
			if offset, ok := timeutil.ParseTimezoneOffsetMinutes(raw); ok {
				ctx = timeutil.WithTimezoneOffsetMinutes(ctx, offset)
			} else if offset, ok := timeutil.OffsetMinutesAt(zone, time.Now()); hasZone && ok {
				ctx = timeutil.WithTimezoneOffsetMinutes(ctx, offset)
			}
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}
