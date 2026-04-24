package timeutil

import (
	"context"
	"testing"
	"time"
)

func TestPeriodStartDateUTCWithPositiveOffset(t *testing.T) {
	ctx := WithTimezoneOffsetMinutes(context.Background(), 420)
	now := time.Date(2026, 2, 9, 18, 30, 0, 0, time.UTC)

	got := PeriodStartDateUTC(ctx, now)
	want := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Fatalf("PeriodStartDateUTC mismatch: got %s want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestPeriodStartDateUTCWithNegativeOffset(t *testing.T) {
	ctx := WithTimezoneOffsetMinutes(context.Background(), -480)
	now := time.Date(2026, 2, 9, 2, 30, 0, 0, time.UTC)

	got := PeriodStartDateUTC(ctx, now)
	want := time.Date(2026, 2, 8, 0, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Fatalf("PeriodStartDateUTC mismatch: got %s want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestNextDayStartUTCWithPositiveOffset(t *testing.T) {
	ctx := WithTimezoneOffsetMinutes(context.Background(), 420)
	now := time.Date(2026, 2, 9, 18, 30, 0, 0, time.UTC)

	got := NextDayStartUTC(ctx, now)
	want := time.Date(2026, 2, 10, 17, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Fatalf("NextDayStartUTC mismatch: got %s want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestSecondsUntilNextDayStartUsesProvidedNow(t *testing.T) {
	ctx := WithTimezoneOffsetMinutes(context.Background(), 0)
	now := time.Date(2026, 2, 9, 23, 59, 0, 0, time.UTC)

	got := SecondsUntilNextDayStart(ctx, now)
	const want = 60

	if got != want {
		t.Fatalf("SecondsUntilNextDayStart mismatch: got %d want %d", got, want)
	}
}

// Pin the exact bug we shipped this package for: a user in EEST (+180)
// crossing their local midnight while server-UTC still says yesterday.
func TestPeriodStartDateUTC_EESTDeadWindowAfterLocalMidnight(t *testing.T) {
	ctx := WithTimezoneOffsetMinutes(context.Background(), 180)

	// Sun 01:30 EEST = Sat 22:30 UTC. User feels it's Sunday.
	now := time.Date(2026, 4, 18, 22, 30, 0, 0, time.UTC)

	got := PeriodStartDateUTC(ctx, now)
	want := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC) // user-Sunday

	if !got.Equal(want) {
		t.Fatalf("EEST midnight crossing: got %s want %s — this is the streak bug", got, want)
	}
}

func TestParseTimezoneOffsetMinutes(t *testing.T) {
	cases := []struct {
		in    string
		want  int
		valid bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"180", 180, true},
		{" -480 ", -480, true},
		{"0", 0, true},
		{"841", 0, false},  // > 14h
		{"-841", 0, false}, // < -14h
		{"abc", 0, false},
		{"180.5", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseTimezoneOffsetMinutes(c.in)
		if got != c.want || ok != c.valid {
			t.Errorf("ParseTimezoneOffsetMinutes(%q) = (%d, %v), want (%d, %v)",
				c.in, got, ok, c.want, c.valid)
		}
	}
}
