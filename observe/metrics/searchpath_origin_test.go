package metrics_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	. "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// An untagged fallback used to log callsite="unknown" and nothing else, which
// is the case where the alert is least actionable: prod 2026-09-22 fired twice
// on kielo-user-service with exactly that and no way to chase it. The warning
// now carries the first frame above this package.
func TestUntaggedFallbackNamesItsOrigin(t *testing.T) {
	ResetPerLanguageSearchPathFallbackState()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	PerLanguageSearchPathFallbackEmit("", false)

	var rec map[string]any
	require := func(cond bool, msg string, args ...any) {
		t.Helper()
		if !cond {
			t.Fatalf(msg, args...)
		}
	}
	require(json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec) == nil,
		"expected one JSON log line, got %q", buf.String())

	require(rec["callsite"] == "unknown", "callsite = %v, want unknown", rec["callsite"])
	origin, ok := rec["origin"].(string)
	require(ok && origin != "", "an untagged fallback must name its origin; got %v", rec["origin"])
	require(strings.Contains(origin, "TestUntaggedFallbackNamesItsOrigin"),
		"origin should point at the caller, got %q", origin)
	// The IMPLEMENTATION package must be skipped; this external test package
	// (observe/metrics_test) is legitimately above it and is what we expect.
	require(!strings.Contains(origin, "observe/metrics."),
		"origin must be the frame ABOVE the implementation package, got %q", origin)
}

// A caller that tagged itself already has the information, so the extra frame
// walk is skipped and the field stays off the line.
func TestTaggedFallbackOmitsOrigin(t *testing.T) {
	ResetPerLanguageSearchPathFallbackState()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	PerLanguageSearchPathFallbackEmit("kielotv.list_brands", false)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("expected one JSON log line, got %q", buf.String())
	}
	if rec["callsite"] != "kielotv.list_brands" {
		t.Fatalf("callsite = %v", rec["callsite"])
	}
	if _, present := rec["origin"]; present {
		t.Fatalf("a tagged callsite needs no origin, got %v", rec["origin"])
	}
}

// The first deploy of the origin walk reported
// "kielo-shared/db/pgxsearchpath.Apply" — technically the frame above this
// package, and useless, because that IS the layer performing the fallback.
// The exclusion has to cover SUBpackages (pkg + "/"), not just the package
// itself (pkg + "."), while still letting sibling *_test packages through.
func TestSharedPlumbingExclusionCoversSubpackages(t *testing.T) {
	for _, tc := range []struct {
		fn       string
		plumbing bool
	}{
		{"github.com/team-kielo-app/kielo-shared/db/pgxsearchpath.Apply", true},
		{"github.com/team-kielo-app/kielo-shared/db.AcquireForLanguage", true},
		{"github.com/team-kielo-app/kielo-shared/observe/metrics.Emit", true},
		// Callers we must NOT hide: the services themselves, and the
		// external test packages that verify this behavior.
		{"kielo.app/user-service/internal/repository.IncrementFeatureUsage", false},
		{"github.com/team-kielo-app/kielo-shared/observe/metrics_test.TestX", false},
		{"github.com/team-kielo-app/kielo-shared/db_test.TestY", false},
		{"github.com/team-kielo-app/kielo-shared/events.Emit", false},
	} {
		if got := IsSharedPlumbingForTest(tc.fn); got != tc.plumbing {
			t.Errorf("isSharedPlumbing(%q) = %v, want %v", tc.fn, got, tc.plumbing)
		}
	}
}
