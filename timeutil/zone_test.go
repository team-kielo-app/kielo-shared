package timeutil

import (
	"context"
	"testing"
	"time"
)

func TestOffsetMinutesAt_FollowsDaylightSaving(t *testing.T) {
	summer := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	winter := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		zone           string
		summer, winter int
	}{
		{"Europe/Helsinki", 180, 120},
		{"Europe/Stockholm", 120, 60},
		{"Europe/Istanbul", 180, 180},
		{"Asia/Kolkata", 330, 330},
	} {
		if got, ok := OffsetMinutesAt(tc.zone, summer); !ok || got != tc.summer {
			t.Errorf("%s summer = %d,%v want %d", tc.zone, got, ok, tc.summer)
		}
		if got, ok := OffsetMinutesAt(tc.zone, winter); !ok || got != tc.winter {
			t.Errorf("%s winter = %d,%v want %d", tc.zone, got, ok, tc.winter)
		}
	}
}

func TestParseTimezoneName_RefusesUnknownAndLocal(t *testing.T) {
	for _, bad := range []string{"", "Local", "Mars/Olympus", "../etc/passwd", "Europe/../../x"} {
		if _, ok := ParseTimezoneName(bad); ok {
			t.Errorf("ParseTimezoneName(%q) accepted", bad)
		}
	}
	if name, ok := ParseTimezoneName(" Europe/Helsinki "); !ok || name != "Europe/Helsinki" {
		t.Errorf("trimmed zone refused: %q %v", name, ok)
	}
}

func TestEffectiveOffsetMinutes_ZoneThenStoredThenUnknown(t *testing.T) {
	winter := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	stored := 180
	if got, _ := EffectiveOffsetMinutes("Europe/Helsinki", &stored, winter); got != 120 {
		t.Errorf("zone must win over a stale summer offset: got %d", got)
	}
	if got, ok := EffectiveOffsetMinutes("", &stored, winter); !ok || got != 180 {
		t.Errorf("no zone: stored offset expected, got %d %v", got, ok)
	}
	if _, ok := EffectiveOffsetMinutes("", nil, winter); ok {
		t.Error("neither known must be unknown")
	}
	if got := DefaultOffsetMinutesAt(winter, ""); got != 120 {
		t.Errorf("default zone in winter = %d, want 120", got)
	}
}

func TestTimezoneNameContext(t *testing.T) {
	ctx := WithTimezoneName(context.Background(), "Mars/Olympus")
	if _, ok := TimezoneNameFromContext(ctx); ok {
		t.Fatal("an invalid zone must not reach the context")
	}
	ctx = WithTimezoneName(context.Background(), "Europe/Stockholm")
	if name, ok := TimezoneNameFromContext(ctx); !ok || name != "Europe/Stockholm" {
		t.Fatalf("got %q %v", name, ok)
	}
}
