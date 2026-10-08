package timeutil

import (
	"context"
	"strings"
	"time"

	// Distroless and scratch images carry no zoneinfo; embed it so a
	// learner's IANA zone always resolves.
	_ "time/tzdata"
)

// TimezoneHeader carries the client's IANA zone name ("Europe/Helsinki").
// It travels with X-Timezone-Offset-Minutes: the offset says where the
// learner's day is right now, the zone says where it will be after a
// daylight-saving change, which background work (notification windows,
// quiet hours) needs because it runs with no request in hand.
const TimezoneHeader = "X-Timezone"

// DefaultTimezone is the zone assumed for a learner who never reported
// one. A zone, not a fixed offset: a fixed +180 is Finnish summer time and
// an hour wrong every winter.
const DefaultTimezone = "Europe/Helsinki"

const timezoneNameCtxKey ctxKey = "timezone_name"

// ParseTimezoneName validates an IANA zone name. "Local" (the server's
// own zone) and names Go's zone database does not know are refused.
func ParseTimezoneName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > 64 || name == "Local" || strings.Contains(name, "..") {
		return "", false
	}
	if _, err := time.LoadLocation(name); err != nil {
		return "", false
	}
	return name, true
}

// WithTimezoneName attaches a validated zone name to ctx.
func WithTimezoneName(ctx context.Context, name string) context.Context {
	if zone, ok := ParseTimezoneName(name); ok {
		return context.WithValue(ctx, timezoneNameCtxKey, zone)
	}
	return ctx
}

// TimezoneNameFromContext returns the zone attached to ctx, if any.
func TimezoneNameFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(timezoneNameCtxKey).(string)
	return name, ok && name != ""
}

// OffsetMinutesAt is the zone's UTC offset at the given instant.
func OffsetMinutesAt(zone string, at time.Time) (int, bool) {
	name, ok := ParseTimezoneName(zone)
	if !ok {
		return 0, false
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return 0, false
	}
	_, seconds := at.In(loc).Zone()
	return seconds / 60, true
}

// EffectiveOffsetMinutes is a learner's UTC offset at an instant, for work
// that runs without their request: their zone when known (correct across
// daylight-saving changes), else the offset their device last reported,
// else unknown. It mirrors SQL users.effective_utc_offset_minutes.
func EffectiveOffsetMinutes(zone string, stored *int, at time.Time) (int, bool) {
	if offset, ok := OffsetMinutesAt(zone, at); ok {
		return offset, true
	}
	if stored != nil {
		return *stored, true
	}
	return 0, false
}

// DefaultOffsetMinutesAt is DefaultTimezone's offset at an instant, for
// learners whose zone and offset are both unknown.
func DefaultOffsetMinutesAt(at time.Time, zone string) int {
	if strings.TrimSpace(zone) == "" {
		zone = DefaultTimezone
	}
	if offset, ok := OffsetMinutesAt(zone, at); ok {
		return offset
	}
	offset, _ := OffsetMinutesAt(DefaultTimezone, at)
	return offset
}
