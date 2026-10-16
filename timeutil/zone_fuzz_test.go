package timeutil

import (
	"context"
	"testing"
	"time"
)

func FuzzParseTimezoneOffsetMinutes(f *testing.F) {
	for _, seed := range []string{"", "0", "180", "-300", "+120", " 60 ", "841", "-841", "1e2", "99999999999999999999", "٣", "0x10"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		offset, ok := ParseTimezoneOffsetMinutes(raw)
		if !ok {
			if offset != 0 {
				t.Fatalf("refused %q but returned offset %d", raw, offset)
			}
			return
		}
		if offset < -14*60 || offset > 14*60 {
			t.Fatalf("accepted out-of-range offset %d from %q", offset, raw)
		}
		ctx := WithTimezoneOffsetMinutes(context.Background(), offset)
		if got, found := LookupTimezoneOffsetMinutesFromContext(ctx); !found || got != offset {
			t.Fatalf("offset %d did not survive the context: %d %t", offset, got, found)
		}
	})
}

func FuzzParseTimezoneName(f *testing.F) {
	for _, seed := range []string{"Europe/Helsinki", " Asia/Ho_Chi_Minh ", "UTC", "Local", "", "../etc/passwd", "Europe/../UTC", "/etc/localtime", "europe/helsinki", "Etc/GMT+5", "zoneinfo.zip", "Europe\\Helsinki", "Europe/Helsinki\x00"} {
		f.Add(seed)
	}
	at := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		name, ok := ParseTimezoneName(raw)
		if !ok {
			if name != "" {
				t.Fatalf("refused %q but returned %q", raw, name)
			}
			return
		}
		if again, ok2 := ParseTimezoneName(name); !ok2 || again != name {
			t.Fatalf("accepted name %q from %q is not stable: %q %t", name, raw, again, ok2)
		}
		offset, found := OffsetMinutesAt(name, at)
		if !found || offset < -14*60 || offset > 14*60 {
			t.Fatalf("zone %q (from %q) gave offset %d found=%t", name, raw, offset, found)
		}
		ctx := WithTimezoneName(context.Background(), raw)
		if got, has := TimezoneNameFromContext(ctx); !has || got != name {
			t.Fatalf("zone %q lost in context: %q %t", name, got, has)
		}
	})
}
