package httputil

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

func TestApplyTimezoneOffsetHeader_StampsFromCtx(t *testing.T) {
	t.Parallel()
	ctx := timeutil.WithTimezoneOffsetMinutes(context.Background(), 180)
	req := httptest.NewRequest("GET", "http://upstream/api/v3/foo", nil)
	req = req.WithContext(ctx)

	ApplyTimezoneOffsetHeader(req)
	if got := req.Header.Get(TimezoneOffsetHeader); got != "180" {
		t.Fatalf("expected X-Timezone-Offset-Minutes=180, got %q", got)
	}
}

func TestApplyTimezoneOffsetHeader_PreservesExplicitCallerOverride(t *testing.T) {
	t.Parallel()
	ctx := timeutil.WithTimezoneOffsetMinutes(context.Background(), 180)
	req := httptest.NewRequest("GET", "http://upstream/api/v3/foo", nil)
	req.Header.Set(TimezoneOffsetHeader, "-300")
	req = req.WithContext(ctx)

	ApplyTimezoneOffsetHeader(req)
	if got := req.Header.Get(TimezoneOffsetHeader); got != "-300" {
		t.Fatalf("expected explicit caller value -300 preserved, got %q", got)
	}
}

func TestApplyTimezoneOffsetHeader_NoOpOnZeroCtxToReduceTraceNoise(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "http://upstream/api/v3/foo", nil)
	// ctx carries no timezone offset; zero is treated as "not set"
	ApplyTimezoneOffsetHeader(req)
	if got := req.Header.Get(TimezoneOffsetHeader); got != "" {
		t.Fatalf("expected empty header on zero ctx, got %q", got)
	}
}
