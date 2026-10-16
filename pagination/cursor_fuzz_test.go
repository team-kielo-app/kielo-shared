package pagination

import "testing"

func FuzzDecodeOffsetCursor(f *testing.F) {
	for _, seed := range []string{"", "0", "20", "-1", "o:20", EncodeOffsetCursor(40), "bzoxMA", "o:-3", "%%%", " 5 ", "9223372036854775807", "99999999999999999999"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		offset, err := DecodeOffsetCursor(cursor)
		if err != nil && offset != 0 {
			t.Fatalf("error %v with offset %d for %q", err, offset, cursor)
		}
		if offset < 0 {
			t.Fatalf("negative offset %d for %q", offset, cursor)
		}
	})
}

func FuzzOffsetCursorRoundTrip(f *testing.F) {
	for _, seed := range []int{0, 1, 20, 1 << 40, -5} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, offset int) {
		encoded := EncodeOffsetCursor(offset)
		if offset <= 0 {
			if encoded != "" {
				t.Fatalf("offset %d encoded to %q", offset, encoded)
			}
			return
		}
		got, err := DecodeOffsetCursor(encoded)
		if err != nil || got != offset {
			t.Fatalf("round trip of %d via %q gave %d, %v", offset, encoded, got, err)
		}
	})
}
