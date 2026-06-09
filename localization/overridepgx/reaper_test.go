package overridepgx

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tests for the stale-row reaper. Mirror the store_test.go skip-if-DB-
// unreachable pattern so dev machines without postgres running don't
// fail; CI sets KIELO_TEST_PG_REQUIRED=1 to make the skip fatal.

// rowsAt returns the rows of `dt` that match (namespace, resource_id)
// — one per (source_version, language_code). Used by tests to check
// status transitions after Reap.
type reaperRowState struct {
	sourceVersion string
	languageCode  string
	status        string
}

func reaperRowStates(t *testing.T, pool *pgxpool.Pool, namespace, resourceID string) []reaperRowState {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `
		SELECT source_version, language_code, status
		  FROM localization.dynamic_translations
		 WHERE resource_type = $1 AND resource_id = $2
		 ORDER BY source_version, language_code
	`, namespace, resourceID)
	if err != nil {
		t.Fatalf("reaperRowStates query: %v", err)
	}
	defer rows.Close()
	var out []reaperRowState
	for rows.Next() {
		var r reaperRowState
		if err := rows.Scan(&r.sourceVersion, &r.languageCode, &r.status); err != nil {
			t.Fatalf("reaperRowStates scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reaperRowStates rows.Err: %v", err)
	}
	return out
}

// seedReaperRow inserts a translation row for a deterministic
// resource_id (so tests can seed multiple versions for the same
// resource and assert the per-version transitions independently).
// Cleanup is registered for the entire (namespace, resource_id) so
// every version+locale variant for that key drops at test end.
//
// `locale` parameter is kept as an argument despite every current
// call passing "vi": future tests will exercise multi-locale per
// stale-row scenarios (e.g. de+vi stale together) and need this
// seam pre-wired. The unparam linter is suppressed because removing
// the param would erase a documented test extension point — same
// rationale as seedRow in store_test.go.
//
//nolint:unparam // see comment above
func seedReaperRow(
	t *testing.T,
	pool *pgxpool.Pool,
	namespace, resourceID, version, locale, status string,
) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO localization.dynamic_translations
		    (resource_type, resource_id, source_version, language_code,
		     translated_text, status, source_locale, translator_source)
		VALUES ($1, $2, $3, $4, $5, $6, 'en', 'test')
		ON CONFLICT (resource_type, resource_id, source_version, language_code)
		DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
	`, namespace, resourceID, version, locale, "stub-translated-"+locale, status)
	if err != nil {
		t.Fatalf("seedReaperRow insert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			DELETE FROM localization.dynamic_translations
			WHERE resource_type=$1 AND resource_id=$2
		`, namespace, resourceID)
	})
}

// staticCurrentSourceVersion builds a CurrentSourceVersionFunc that
// returns a fixed source_version for a known set of resource_ids and
// (false) for anything else. Useful when tests want a closed-world
// "I know exactly these keys" stance.
func staticCurrentSourceVersion(known map[string]string) CurrentSourceVersionFunc {
	return func(_ context.Context, _, resourceID string) (string, bool) {
		v, ok := known[resourceID]
		return v, ok
	}
}

// TestReaper_FlipsStaleRowsToPendingReview is the headline behavior
// pin: one stale row + one fresh row + one already-pending row →
// only the stale one gets flipped.
func TestReaper_FlipsStaleRowsToPendingReview(t *testing.T) {
	pool := newPool(t)
	namespace := "ui.string"
	staleRID := "test-stale-" + uuid.NewString()
	freshRID := "test-fresh-" + uuid.NewString()
	pendingRID := "test-pending-" + uuid.NewString()

	// Stale: stored source_version "old-v1" but current is "new-v2".
	seedReaperRow(t, pool, namespace, staleRID, "old-v1", "vi", "machine")
	// Fresh: stored source_version matches current.
	seedReaperRow(t, pool, namespace, freshRID, "current-v1", "vi", "machine")
	// Already-pending: stale source_version but status='pending_review'
	// — reaper must skip (idempotency).
	seedReaperRow(t, pool, namespace, pendingRID, "old-v1", "vi", "pending_review")

	current := staticCurrentSourceVersion(map[string]string{
		staleRID:   "new-v2",
		freshRID:   "current-v1",
		pendingRID: "new-v2",
	})

	reaper := NewReaper(pool, current, WithResourceTypeFilter(namespace), WithResourceIDPrefix("test-"))
	stats, err := reaper.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if stats.Stale != 1 {
		t.Errorf("Stale = %d, want 1", stats.Stale)
	}
	if stats.Fresh != 1 {
		t.Errorf("Fresh = %d, want 1", stats.Fresh)
	}
	// Scanned counts every row the scan returned (which excludes
	// rows already at pending_review via the WHERE clause). So
	// stale + fresh = 2, NOT 3.
	if stats.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2 (the already-pending row is excluded by the scan WHERE)", stats.Scanned)
	}
	if got := stats.PerLocale["vi"]; got != 1 {
		t.Errorf("PerLocale[vi] = %d, want 1", got)
	}
	if got := stats.PerResourceType[namespace]; got != 1 {
		t.Errorf("PerResourceType[%s] = %d, want 1", namespace, got)
	}

	// DB state: stale → pending_review; fresh → still machine;
	// already-pending → still pending_review.
	staleRows := reaperRowStates(t, pool, namespace, staleRID)
	if len(staleRows) != 1 || staleRows[0].status != "pending_review" {
		t.Errorf("stale row state = %+v, want status=pending_review", staleRows)
	}
	freshRows := reaperRowStates(t, pool, namespace, freshRID)
	if len(freshRows) != 1 || freshRows[0].status != "machine" {
		t.Errorf("fresh row state = %+v, want status=machine", freshRows)
	}
	pendingRows := reaperRowStates(t, pool, namespace, pendingRID)
	if len(pendingRows) != 1 || pendingRows[0].status != "pending_review" {
		t.Errorf("already-pending row state = %+v, want status=pending_review (unchanged)", pendingRows)
	}
}

// TestReaper_UnknownResourcesAreSkipped pins the "current returns
// false" contract: rows whose resource_id the caller doesn't recognize
// are left alone (no flip, counted as Unknown in stats).
func TestReaper_UnknownResourcesAreSkipped(t *testing.T) {
	pool := newPool(t)
	namespace := "ui.string"
	knownRID := "test-known-" + uuid.NewString()
	unknownRID := "test-unknown-" + uuid.NewString()

	seedReaperRow(t, pool, namespace, knownRID, "old", "vi", "machine")
	seedReaperRow(t, pool, namespace, unknownRID, "old", "vi", "machine")

	current := staticCurrentSourceVersion(map[string]string{
		knownRID: "new",
		// unknownRID intentionally omitted → CurrentSourceVersionFunc
		// returns (_, false) for it.
	})
	reaper := NewReaper(pool, current, WithResourceTypeFilter(namespace), WithResourceIDPrefix("test-"))
	stats, err := reaper.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if stats.Stale != 1 {
		t.Errorf("Stale = %d, want 1 (only the known stale row)", stats.Stale)
	}
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1 (the row whose resource_id is unknown)", stats.Unknown)
	}

	unknownRows := reaperRowStates(t, pool, namespace, unknownRID)
	if len(unknownRows) != 1 || unknownRows[0].status != "machine" {
		t.Errorf("unknown row state = %+v, want status=machine (left alone)", unknownRows)
	}
}

// TestReaper_IsIdempotent pins: calling Reap twice in a row over the
// same DB state produces (stale=N, then stale=0). The second pass
// sees the now-flipped rows excluded by the scan WHERE clause.
func TestReaper_IsIdempotent(t *testing.T) {
	pool := newPool(t)
	namespace := "ui.string"
	rid := "test-idem-" + uuid.NewString()
	seedReaperRow(t, pool, namespace, rid, "old", "vi", "machine")

	current := staticCurrentSourceVersion(map[string]string{rid: "new"})
	reaper := NewReaper(pool, current, WithResourceTypeFilter(namespace), WithResourceIDPrefix("test-"))

	stats1, err := reaper.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap 1: %v", err)
	}
	if stats1.Stale != 1 {
		t.Fatalf("first pass Stale = %d, want 1", stats1.Stale)
	}

	stats2, err := reaper.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap 2: %v", err)
	}
	if stats2.Stale != 0 {
		t.Errorf("second pass Stale = %d, want 0 (already flipped)", stats2.Stale)
	}
	if stats2.Scanned != 0 {
		t.Errorf("second pass Scanned = %d, want 0 (pending_review rows are excluded)", stats2.Scanned)
	}
}

// TestReaper_RespectsResourceTypeFilter pins: when a filter is set,
// the reaper only touches rows of that type, even if other types have
// stale rows.
func TestReaper_RespectsResourceTypeFilter(t *testing.T) {
	pool := newPool(t)
	rid := "test-filter-" + uuid.NewString()
	// Two rows for the same resource_id but DIFFERENT resource_types.
	// The reaper is filtered to namespace1, so namespace2's stale
	// row must NOT be touched.
	namespace1 := "ui.string"
	namespace2 := "scenario.description"
	seedReaperRow(t, pool, namespace1, rid, "old", "vi", "machine")
	seedReaperRow(t, pool, namespace2, rid, "old", "vi", "machine")

	current := staticCurrentSourceVersion(map[string]string{rid: "new"})
	reaper := NewReaper(pool, current, WithResourceTypeFilter(namespace1), WithResourceIDPrefix("test-"))
	stats, err := reaper.Reap(context.Background())
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if stats.Stale != 1 {
		t.Errorf("Stale = %d, want 1 (only the filtered resource_type)", stats.Stale)
	}

	ns2Rows := reaperRowStates(t, pool, namespace2, rid)
	if len(ns2Rows) != 1 || ns2Rows[0].status != "machine" {
		t.Errorf("namespace2 row state = %+v, want status=machine (out of filter)", ns2Rows)
	}
}

// TestReaper_NilPoolErrors guards against silent no-ops. The reaper
// is the kind of thing that, if misconfigured, fails silently and
// never flags stale rows — so callers MUST get a loud error at the
// Reap call rather than discovering empty stats months later.
func TestReaper_NilPoolErrors(t *testing.T) {
	reaper := NewReaper(nil, staticCurrentSourceVersion(map[string]string{}))
	_, err := reaper.Reap(context.Background())
	if err == nil {
		t.Fatal("Reap with nil pool: want error, got nil")
	}
	if !errors.Is(err, err) { // tautology — any non-nil err satisfies
		t.Skip("err type guard not needed; nil check above is the assertion")
	}
}

// TestReaper_NilCurrentFuncErrors is the companion pin: a missing
// CurrentSourceVersionFunc would mean every row gets classified as
// Unknown and never flipped, silently defeating the reaper. Loud
// error at Reap time instead.
func TestReaper_NilCurrentFuncErrors(t *testing.T) {
	pool := newPool(t)
	reaper := NewReaper(pool, nil)
	_, err := reaper.Reap(context.Background())
	if err == nil {
		t.Fatal("Reap with nil CurrentSourceVersionFunc: want error, got nil")
	}
}
