// Package timeutil provides timezone-aware day-boundary helpers.
//
// All Kielo backend services run UTC, but per-user "today" must roll over
// at the user's local midnight. The mobile client sends the offset on
// every request via X-Timezone-Offset-Minutes (see kielo-app baseQuery);
// the BFF forwards it; downstream services parse it into context with
// WithTimezoneOffsetHeader and then derive day boundaries with
// PeriodStartDateUTC / DayStartUTC / NextDayStartUTC.
//
// Why this exists in kielo-shared rather than per-service: the previous
// duplicates drifted (user-service used the helper for feature usage but
// the streak code was written with raw time.Now().Truncate(24*time.Hour),
// which silently dropped streak increments for any user east or west
// enough of UTC to cross a day boundary while the server still believed
// it was "yesterday"). One package, one truth, one place to add tests.
package timeutil

import (
	"context"
	"strconv"
	"strings"
	"time"
)

const (
	// TimezoneOffsetHeader is the HTTP header carrying the client's UTC
	// offset in minutes. Example: Helsinki summer (EEST) is +180; US
	// Pacific winter (PST) is -480.
	TimezoneOffsetHeader = "X-Timezone-Offset-Minutes"

	minTimezoneOffsetMinutes = -14 * 60
	maxTimezoneOffsetMinutes = 14 * 60
)

type ctxKey string

const timezoneOffsetMinutesCtxKey ctxKey = "timezone_offset_minutes"

// ParseTimezoneOffsetMinutes parses a header value into an offset in
// minutes. Returns (0, false) for empty, malformed, or out-of-range
// inputs (clamps at ±14h, beyond which IANA does not assign zones).
func ParseTimezoneOffsetMinutes(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	offsetMinutes, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	if offsetMinutes < minTimezoneOffsetMinutes || offsetMinutes > maxTimezoneOffsetMinutes {
		return 0, false
	}
	return offsetMinutes, true
}

// WithTimezoneOffsetMinutes attaches a validated offset (in minutes) to ctx.
func WithTimezoneOffsetMinutes(ctx context.Context, offsetMinutes int) context.Context {
	if offsetMinutes < minTimezoneOffsetMinutes || offsetMinutes > maxTimezoneOffsetMinutes {
		return ctx
	}
	return context.WithValue(ctx, timezoneOffsetMinutesCtxKey, offsetMinutes)
}

// WithTimezoneOffsetHeader is the convenience entry point for HTTP
// handlers: pass the raw header value, get a derived context.
func WithTimezoneOffsetHeader(ctx context.Context, headerValue string) context.Context {
	offsetMinutes, ok := ParseTimezoneOffsetMinutes(headerValue)
	if !ok {
		return ctx
	}
	return WithTimezoneOffsetMinutes(ctx, offsetMinutes)
}

// TimezoneOffsetMinutesFromContext returns the offset attached to ctx, or
// 0 if none. Callers that need to preserve the offset across goroutines
// (fire-and-forget background work) should read it here and re-attach to
// the new context with WithTimezoneOffsetMinutes.
func TimezoneOffsetMinutesFromContext(ctx context.Context) int {
	value := ctx.Value(timezoneOffsetMinutesCtxKey)
	if value == nil {
		return 0
	}
	offsetMinutes, ok := value.(int)
	if !ok {
		return 0
	}
	return offsetMinutes
}

func timezoneOffsetDuration(ctx context.Context) time.Duration {
	return time.Duration(TimezoneOffsetMinutesFromContext(ctx)) * time.Minute
}

// DayStartUTC returns the UTC instant corresponding to the start of the
// user's current local day. Use this when comparing against stored
// timestamps (e.g. last_active_date).
func DayStartUTC(ctx context.Context, now time.Time) time.Time {
	offset := timezoneOffsetDuration(ctx)
	nowUTC := now.UTC()
	localNow := nowUTC.Add(offset)

	year, month, day := localNow.Date()
	localMidnight := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return localMidnight.Add(-offset)
}

// PeriodStartDateUTC returns the user's "today" as a date-only timestamp
// (year/month/day, 00:00:00 UTC). Use this when writing to a DATE column
// like users.feature_usage.period_start or users.users.last_active_date —
// the result is the same for all users in the same local calendar day,
// independent of TZ.
func PeriodStartDateUTC(ctx context.Context, now time.Time) time.Time {
	localNow := now.UTC().Add(timezoneOffsetDuration(ctx))
	year, month, day := localNow.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// NextDayStartUTC returns the UTC instant of the user's next local
// midnight. Use this for "limit resets at" timestamps surfaced to clients.
func NextDayStartUTC(ctx context.Context, now time.Time) time.Time {
	return DayStartUTC(ctx, now).AddDate(0, 0, 1)
}

// SecondsUntilNextDayStart returns the seconds remaining until the user's
// next local midnight. Returns 0 (not negative) if `now` already crossed.
func SecondsUntilNextDayStart(ctx context.Context, now time.Time) int {
	seconds := int(NextDayStartUTC(ctx, now).Sub(now.UTC()).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}
