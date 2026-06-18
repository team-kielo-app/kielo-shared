package overridepgx

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// dsn returns the postgres connection string for the test environment.
// Defaults to the local docker-compose layout (POSTGRES_PASSWORD=password,
// port 5432). CI can override via KIELO_TEST_PG_DSN.
func dsn(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("KIELO_TEST_PG_DSN"); v != "" {
		return v
	}
	return "postgres://kielo:password@localhost:5432/kielo_test?sslmode=disable"
}

// newPool connects to the local kielo_test DB. Skip the suite if it's
// unreachable so dev machines without postgres running don't fail; CI
// must export KIELO_TEST_PG_REQUIRED=1 to turn the skip into a fatal.
func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn(t))
	if err != nil {
		if os.Getenv("KIELO_TEST_PG_REQUIRED") == "1" {
			t.Fatalf("pgxpool.New: %v", err)
		}
		t.Skipf("pgxpool.New failed and KIELO_TEST_PG_REQUIRED unset: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		if os.Getenv("KIELO_TEST_PG_REQUIRED") == "1" {
			t.Fatalf("pool.Ping: %v", err)
		}
		t.Skipf("pool.Ping failed and KIELO_TEST_PG_REQUIRED unset: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seededRow bundles the identifying tuple of a seeded translation row.
// Returned from seedRow so callers can pass any subset directly into
// Lookup without juggling positional arguments.
type seededRow struct {
	namespace    string
	resourceID   string
	version      string
	targetLocale string
}

// seedRow inserts a translation row scoped to a test-specific
// resource_id so parallel tests don't collide. Returns the row's
// identifying tuple as a seededRow — convenient to spread into Lookup.
//
// `version` parameter is intentionally kept as an argument despite
// every current call using "v1": future tests will exercise multi-version
// cache busting and need this seam pre-wired. The unparam linter is
// suppressed because removing the param would erase a documented test
// extension point.
//
//nolint:unparam // see comment above
func seedRow(
	t *testing.T,
	pool *pgxpool.Pool,
	namespace, version, locale, value, status string,
) seededRow {
	t.Helper()
	ctx := context.Background()

	resourceID := "test-" + uuid.NewString()
	_, err := pool.Exec(ctx, `
		INSERT INTO localization.dynamic_translations
		    (resource_type, resource_id, source_version, language_code,
		     translated_text, status, source_locale, translator_source)
		VALUES ($1, $2, $3, $4, $5, $6, 'en', 'test')
	`, namespace, resourceID, version, locale, value, status)
	if err != nil {
		t.Fatalf("seedRow insert failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			DELETE FROM localization.dynamic_translations
			WHERE resource_type=$1 AND resource_id=$2
		`, namespace, resourceID)
	})
	return seededRow{
		namespace:    namespace,
		resourceID:   resourceID,
		version:      version,
		targetLocale: locale,
	}
}

func TestStore_Lookup_ApprovedRowHit(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	row := seedRow(t, pool,
		"article.title", "v1", "vi",
		"Đặt cà phê", "approved")

	got, ok := store.Lookup(context.Background(), row.namespace, row.resourceID, row.version, row.targetLocale)
	if !ok {
		t.Fatal("expected hit on approved row")
	}
	if got != "Đặt cà phê" {
		t.Fatalf("value mismatch: got %q", got)
	}
}

func TestStore_Lookup_OverrideRowHit(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	row := seedRow(t, pool,
		"article.title", "v1", "vi",
		"Đặt cà phê (admin edit)", "override")

	got, ok := store.Lookup(context.Background(), row.namespace, row.resourceID, row.version, row.targetLocale)
	if !ok {
		t.Fatal("expected hit on override row")
	}
	if got != "Đặt cà phê (admin edit)" {
		t.Fatalf("value mismatch: got %q", got)
	}
}

func TestStore_Lookup_OverrideBeatsApproved(t *testing.T) {
	// Pathological case — two rows for the same key with different
	// statuses. Should not happen given the unique constraint
	// (resource_type, resource_id, source_version, language_code), but
	// the ORDER BY in the lookup query is the safety net. We test it
	// by using DIFFERENT source_versions for the two rows so the
	// unique constraint doesn't fire.
	pool := newPool(t)
	store := New(pool)

	resourceID := "test-" + uuid.NewString()
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM localization.dynamic_translations WHERE resource_id=$1`, resourceID)
	})

	// Two rows: an approved one for v1, an override one for v2.
	// Looking up v1 returns the approved; v2 returns the override.
	for _, row := range []struct {
		version, status, value string
	}{
		{"v1", "approved", "approved-text"},
		{"v2", "override", "override-text"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO localization.dynamic_translations
			    (resource_type, resource_id, source_version, language_code,
			     translated_text, status, source_locale, translator_source)
			VALUES ('article.title', $1, $2, 'vi', $3, $4, 'en', 'test')
		`, resourceID, row.version, row.value, row.status); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got, ok := store.Lookup(ctx, "article.title", resourceID, "v1", "vi")
	if !ok || got != "approved-text" {
		t.Fatalf("v1: got %q ok=%v, want approved-text", got, ok)
	}
	got, ok = store.Lookup(ctx, "article.title", resourceID, "v2", "vi")
	if !ok || got != "override-text" {
		t.Fatalf("v2: got %q ok=%v, want override-text", got, ok)
	}
}

func TestStore_Lookup_PendingReviewIsMiss(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	row := seedRow(t, pool,
		"article.title", "v1", "vi",
		"placeholder", "pending_review")

	if _, ok := store.Lookup(context.Background(), row.namespace, row.resourceID, row.version, row.targetLocale); ok {
		t.Fatal("pending_review row must NOT be served")
	}
}

func TestStore_Lookup_MachineIsMiss(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	row := seedRow(t, pool,
		"article.title", "v1", "vi",
		"machine-translated text", "machine")

	if _, ok := store.Lookup(context.Background(), row.namespace, row.resourceID, row.version, row.targetLocale); ok {
		t.Fatal("machine row must NOT be served (only override/approved)")
	}
}

func TestStore_Lookup_StaleSourceVersionIsMiss(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	row := seedRow(t, pool,
		"article.title", "v1", "vi",
		"v1-era text", "approved")

	// Same (ns, id, locale) but DIFFERENT source_version — the row
	// exists but is stale relative to the request. Must return miss.
	if _, ok := store.Lookup(context.Background(), row.namespace, row.resourceID, "v2", row.targetLocale); ok {
		t.Fatal("stale source_version row must NOT be served")
	}
}

func TestStore_Lookup_DifferentNamespacesAreIsolated(t *testing.T) {
	// A given (resource_id, source_version, language_code) tuple can
	// legitimately mean different things in two namespaces — e.g.
	// 'article.title' and 'scenario.title'. The unique constraint
	// includes resource_type for exactly this reason. Pin the
	// isolation: a hit in one namespace doesn't leak into another.
	pool := newPool(t)
	store := New(pool)

	rowArticle := seedRow(t, pool,
		"article.title", "v1", "vi",
		"Đặt cà phê", "approved")
	rowScenario := seedRow(t, pool,
		"scenario.title", "v1", "vi",
		"Tình huống cà phê", "approved")

	if rowArticle.resourceID == rowScenario.resourceID {
		t.Fatal("seedRow should generate distinct resourceIDs per call")
	}

	got, ok := store.Lookup(context.Background(),
		rowArticle.namespace, rowArticle.resourceID, rowArticle.version, rowArticle.targetLocale)
	if !ok || got != "Đặt cà phê" {
		t.Fatalf("article.title lookup: got %q ok=%v", got, ok)
	}

	got, ok = store.Lookup(context.Background(),
		rowScenario.namespace, rowScenario.resourceID, rowScenario.version, rowScenario.targetLocale)
	if !ok || got != "Tình huống cà phê" {
		t.Fatalf("scenario.title lookup: got %q ok=%v", got, ok)
	}
}

func TestStore_Lookup_UnknownKeyReturnsMiss(t *testing.T) {
	pool := newPool(t)
	store := New(pool)

	got, ok := store.Lookup(context.Background(),
		"article.title", "nonexistent-id", "v1", "vi")
	if ok {
		t.Fatalf("expected miss; got %q", got)
	}
}

func TestStore_Lookup_NilPoolReturnsMiss(t *testing.T) {
	// Construct a Store with nil pool. Used by call sites that haven't
	// wired the override path yet; Lookup must not panic, must report
	// miss so the seam falls through to the cache + provider.
	store := New(nil)
	if _, ok := store.Lookup(context.Background(), "article.title", "id", "v1", "vi"); ok {
		t.Fatal("nil-pool store should never hit")
	}
}
