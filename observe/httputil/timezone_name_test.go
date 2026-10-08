package httputil

import (
	"context"
	"net/http"
	"testing"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

func TestApplyTimezoneOffsetHeader_ForwardsZone(t *testing.T) {
	ctx := timeutil.WithTimezoneName(context.Background(), "Europe/Stockholm")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://user-service/x", nil)
	ApplyTimezoneOffsetHeader(req)
	if got := req.Header.Get(timeutil.TimezoneHeader); got != "Europe/Stockholm" {
		t.Fatalf("X-Timezone = %q", got)
	}

	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://user-service/x", nil)
	req.Header.Set(timeutil.TimezoneHeader, "Asia/Tokyo")
	ApplyTimezoneOffsetHeader(req)
	if got := req.Header.Get(timeutil.TimezoneHeader); got != "Asia/Tokyo" {
		t.Fatalf("an explicit header must win, got %q", got)
	}
}
