// Package overridepgx — stale-row reaper.
//
// The Store.Lookup read path filters stale rows server-side via the
// source_version predicate, so the seam never serves them. That's
// good for correctness but bad for observability: a row whose English
// source was edited after the translation was authored just silently
// stops being served, and the admin has no signal that it needs
// re-translation.
//
// The reaper flips stale rows from `status='machine'/'approved'/'override'`
// to `status='pending_review'` so they appear in the admin Translation
// Audit queue (Phase 8 admin surface). Operators see the stale row,
// confirm the new English text, and either approve or re-author the
// translation — which writes a fresh row with the current
// source_version and unblocks the seam.
//
// Design contract:
//
//   - The reaper does NOT know what the "current" source_version is
//     for any given (resource_type, resource_id) — that lives in code
//     (seed registries, content tables, etc.). Callers supply a
//     CurrentSourceVersionFunc that maps (resource_type, resource_id)
//     to the live source_version. Returning ("", false) signals
//     "I don't know — leave this row alone".
//
//   - Reap is idempotent. A row already at status='pending_review'
//     is skipped. A row whose source_version MATCHES the current
//     value is left alone (it's fresh, the seam is serving it).
//
//   - Reap reports the number of rows flipped per (resource_type,
//     locale) bucket so dashboards can alert on sudden spikes.
//
//   - Reap is INTENTIONALLY not a long-running goroutine. Callers wire
//     it to their preferred scheduler (Cloud Scheduler, kubernetes
//     CronJob, in-process ticker). The reaper itself runs one pass
//     per Reap() call.
//
// Failure mode: any error during the scan or update batch logs and
// returns. The seam read path is unaffected because the reaper only
// touches rows the seam was already filtering out.
package overridepgx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CurrentSourceVersionFunc resolves the current source_version for a
// (resource_type, resource_id) tuple. Returns ("", false) when the
// caller doesn't recognize the resource — the reaper leaves those
// rows alone (a deprecated key still in the DB is a separate cleanup
// concern; the reaper's job is "flag stale, not delete unknown").
type CurrentSourceVersionFunc func(ctx context.Context, resourceType, resourceID string) (sourceVersion string, known bool)

// Reaper flips stale localization.dynamic_translations rows to
// status='pending_review' so they surface in the admin audit queue.
// See package doc for design rationale.
type Reaper struct {
	pool    *pgxpool.Pool
	current CurrentSourceVersionFunc

	// scanBatchSize bounds memory + lock duration. Reads run in
	// batches of this size; the reaper applies updates per-batch so
	// long-running scans never hold a single large lock. Defaults
	// to 500 (set via WithScanBatchSize).
	scanBatchSize int

	// resourceTypeFilter, when non-empty, restricts the scan to
	// rows of that resource_type. Useful when callers wire one
	// reaper per resource family. Empty = scan all resource types.
	resourceTypeFilter string

	// resourceIDPrefix, when non-empty, restricts the scan to rows
	// whose resource_id starts with this string (SQL LIKE 'prefix%').
	// Sweep Round 7 (2026-06-09): added for test-fixture scoping
	// after the Round 6 C3 verification probe left a stray
	// `ui.engine_string.Learn` row in the dev DB that contaminated
	// the reaper's own test suite via the shared `ui.string`
	// resource_type. Production wirings leave this empty; tests can
	// scope to `WithResourceIDPrefix("test-")` to avoid
	// cross-fixture interference. Same shape as Sweep TTTTT's
	// scenario test cleanup hooks at the registry-scan layer.
	resourceIDPrefix string
}

// New constructs a Reaper. Pool must be non-nil in production;
// current resolves the live source_version. Apply Option values for
// non-default knobs.
func NewReaper(pool *pgxpool.Pool, current CurrentSourceVersionFunc, opts ...ReaperOption) *Reaper {
	r := &Reaper{
		pool:          pool,
		current:       current,
		scanBatchSize: 500,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ReaperOption mutates a Reaper at construction time.
type ReaperOption func(*Reaper)

// WithScanBatchSize sets the per-batch row limit. Defaults to 500.
// Values <= 0 are ignored.
func WithScanBatchSize(n int) ReaperOption {
	return func(r *Reaper) {
		if n > 0 {
			r.scanBatchSize = n
		}
	}
}

// WithResourceTypeFilter restricts the scan to one resource_type.
// Useful when wiring per-resource reapers (one for ui.string, one
// for scenario.description, etc.) so each can have its own scheduler
// cadence and CurrentSourceVersionFunc. Empty string = scan all.
func WithResourceTypeFilter(resourceType string) ReaperOption {
	return func(r *Reaper) {
		r.resourceTypeFilter = resourceType
	}
}

// WithResourceIDPrefix restricts the scan to rows whose resource_id
// starts with the given prefix. Useful for test fixtures that share
// a resource_type with other writers (e.g. tests for the `ui.string`
// reaper should scope to a unique resource_id prefix to avoid being
// affected by stray rows from manual probes or other test fixtures).
//
// Sweep Round 7 (2026-06-09): added after the Round 6 C3 verification
// probe left a stray `ui.engine_string.Learn` row in the dev DB,
// contaminating the reaper's own test suite. Production wirings
// leave this empty; tests can pass `WithResourceIDPrefix("test-")`
// to scope to test-namespaced rows only.
//
// Empty string = no prefix filter (scan all matching rows).
func WithResourceIDPrefix(prefix string) ReaperOption {
	return func(r *Reaper) {
		r.resourceIDPrefix = prefix
	}
}

// ReapStats reports what one Reap pass did. Counts are per-bucket so
// dashboards can alert on per-locale or per-resource-type spikes.
type ReapStats struct {
	// Scanned is the total number of rows the reaper looked at this
	// pass (regardless of whether they were stale or fresh).
	Scanned int
	// Stale is the count of rows whose source_version did NOT match
	// the current value AND whose status was not already
	// 'pending_review'. These were flipped.
	Stale int
	// Unknown is the count of rows the CurrentSourceVersionFunc
	// declined to resolve (returned ok=false). These were skipped.
	Unknown int
	// Fresh is the count of rows whose source_version matched the
	// current value. These were left alone.
	Fresh int
	// PerLocale records the per-locale Stale count so dashboards
	// can pivot. Keyed by language_code.
	PerLocale map[string]int
	// PerResourceType records the per-resource_type Stale count.
	PerResourceType map[string]int
	// Duration is the wall-clock duration of the Reap pass.
	Duration time.Duration
}

// Reap runs one scan-and-flip pass. Idempotent — calling repeatedly
// on a clean DB is a no-op. Returns stats describing what happened.
//
// Error path: any error during the scan or update batch logs and
// returns whatever stats were collected so far. The seam read path
// is unaffected because the reaper only touches rows the seam was
// already filtering out.
func (r *Reaper) Reap(ctx context.Context) (ReapStats, error) {
	start := time.Now()
	stats := ReapStats{
		PerLocale:       map[string]int{},
		PerResourceType: map[string]int{},
	}
	if r == nil || r.pool == nil || r.current == nil {
		return stats, errors.New("overridepgx.Reaper.Reap: nil pool or current func")
	}

	// One pass = repeated batched reads until the cursor drains.
	// Each batch processes rows that haven't been flipped yet
	// (excludes status='pending_review'). The cursor advances by
	// (resource_type, resource_id, source_version, language_code)
	// — the unique-index columns — so batches don't re-scan the
	// same rows even if updates churn them.
	var cursor scanCursor
	for {
		batch, err := r.scanBatch(ctx, cursor)
		if err != nil {
			stats.Duration = time.Since(start)
			return stats, fmt.Errorf("reaper scan: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		var staleIDs []scanRow
		for _, row := range batch {
			stats.Scanned++
			cursor = row.cursor()
			currentVersion, known := r.current(ctx, row.ResourceType, row.ResourceID)
			if !known {
				stats.Unknown++
				continue
			}
			if currentVersion == row.SourceVersion {
				stats.Fresh++
				continue
			}
			staleIDs = append(staleIDs, row)
		}

		if len(staleIDs) > 0 {
			flipped, err := r.flipBatch(ctx, staleIDs)
			if err != nil {
				log.Printf(
					"WARN: overridepgx.Reaper flip-batch failed (continuing scan): %v", err,
				)
				continue
			}
			stats.Stale += flipped
			for _, row := range staleIDs {
				stats.PerLocale[row.LanguageCode]++
				stats.PerResourceType[row.ResourceType]++
			}
		}

		if len(batch) < r.scanBatchSize {
			// Last page — drained.
			break
		}
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// scanCursor is the keyset-pagination cursor used by scanBatch.
// Zero value scans from the start.
type scanCursor struct {
	ResourceType  string
	ResourceID    string
	SourceVersion string
	LanguageCode  string
}

// scanRow is one row from the reaper's scan query — the fields we
// need to (a) decide whether it's stale and (b) update it if so.
// scanRow's field layout matches scanCursor exactly so scanRow can
// trivially convert to scanCursor for keyset pagination.
type scanRow scanCursor

func (r scanRow) cursor() scanCursor {
	return scanCursor(r)
}

func (c scanCursor) isZero() bool {
	return c.ResourceType == "" && c.ResourceID == "" && c.SourceVersion == "" && c.LanguageCode == ""
}

// scanBatch reads one batch of rows past the cursor. Excludes rows
// already at status='pending_review' so the reaper doesn't churn
// rows it already flipped on a previous pass. ORDER BY matches the
// unique-index column order so the keyset pagination is index-only.
//
// scanResourceTypeFilter is applied as a literal predicate (single
// resource_type per reaper instance is the typical wiring).
const baseScanQuery = `
	SELECT resource_type, resource_id, source_version, language_code
	  FROM localization.dynamic_translations
	 WHERE status <> 'pending_review'
`

func (r *Reaper) scanBatch(ctx context.Context, cursor scanCursor) ([]scanRow, error) {
	query := baseScanQuery
	args := []any{}
	argIdx := 1
	if r.resourceTypeFilter != "" {
		query += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, r.resourceTypeFilter)
		argIdx++
	}
	if r.resourceIDPrefix != "" {
		// PostgreSQL LIKE pattern: append '%' wildcard at runtime so
		// callers don't have to think about it. Standard SQL escape
		// rules apply to the prefix; per-caller it's typically a
		// constant ("test-") so no user-input injection vector.
		query += fmt.Sprintf(" AND resource_id LIKE $%d", argIdx)
		args = append(args, r.resourceIDPrefix+"%")
		argIdx++
	}
	if !cursor.isZero() {
		// Keyset pagination on the unique index. The four-column
		// tuple comparison maps directly to the index ORDER BY.
		query += fmt.Sprintf(
			" AND (resource_type, resource_id, source_version, language_code) > ($%d, $%d, $%d, $%d)",
			argIdx, argIdx+1, argIdx+2, argIdx+3,
		)
		args = append(args, cursor.ResourceType, cursor.ResourceID, cursor.SourceVersion, cursor.LanguageCode)
		argIdx += 4
	}
	query += fmt.Sprintf(
		" ORDER BY resource_type, resource_id, source_version, language_code LIMIT $%d",
		argIdx,
	)
	args = append(args, r.scanBatchSize)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var batch []scanRow
	for rows.Next() {
		var row scanRow
		if err := rows.Scan(&row.ResourceType, &row.ResourceID, &row.SourceVersion, &row.LanguageCode); err != nil {
			return nil, err
		}
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

// flipBatch updates the listed rows to status='pending_review' in one
// statement. Idempotent at the row level: the WHERE clause excludes
// rows already at 'pending_review' so a concurrent flip is harmless.
//
// Returns the count of rows actually flipped (UPDATE row count).
const flipQuery = `
	UPDATE localization.dynamic_translations
	   SET status     = 'pending_review',
	       updated_at = NOW()
	 WHERE status     <> 'pending_review'
	   AND (resource_type, resource_id, source_version, language_code) = ANY($1)
`

func (r *Reaper) flipBatch(ctx context.Context, rows []scanRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	// Build a TEXT[][] tuple array compatible with the
	// `(...) = ANY($1)` clause. pgx encodes [][]string as a 2D
	// TEXT array; the row composite comparison in the predicate
	// matches that shape via the implicit ROW(...) cast.
	//
	// We use individual rows rather than splitting into 4 ANY
	// arrays because the unique-index tuple comparison is the
	// only shape that selects each row exactly once without
	// over-matching (e.g. resource_id=X AND any source_version
	// would match unrelated rows).
	tuples := make([][]string, len(rows))
	for i, row := range rows {
		tuples[i] = []string{row.ResourceType, row.ResourceID, row.SourceVersion, row.LanguageCode}
	}

	// Postgres doesn't have a native "tuple ANY" syntax against a
	// 2D array; fall back to a generated VALUES list. Bounded by
	// scanBatchSize (default 500) so the per-statement parameter
	// count stays well under Postgres's 32767 limit.
	values, args := buildTupleValues(tuples)
	query := fmt.Sprintf(`
		UPDATE localization.dynamic_translations dt
		   SET status     = 'pending_review',
		       updated_at = NOW()
		  FROM (VALUES %s) AS stale(rt, rid, sv, lc)
		 WHERE dt.status         <> 'pending_review'
		   AND dt.resource_type   = stale.rt
		   AND dt.resource_id     = stale.rid
		   AND dt.source_version  = stale.sv
		   AND dt.language_code   = stale.lc
	`, values)
	_ = flipQuery // retained for documentation; the ANY shape is unused

	tag, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// buildTupleValues turns N row-tuples into a VALUES (...), (...), ...
// fragment plus the flat argument slice they reference. Used by
// flipBatch to avoid the absent "tuple = ANY(array)" syntax.
func buildTupleValues(rows [][]string) (fragment string, args []any) {
	args = make([]any, 0, len(rows)*4)
	out := make([]byte, 0, len(rows)*32)
	for i, row := range rows {
		if i > 0 {
			out = append(out, ',', ' ')
		}
		base := i * 4
		out = append(out, '(')
		for j, v := range row {
			if j > 0 {
				out = append(out, ',', ' ')
			}
			out = append(out, fmt.Sprintf("$%d", base+j+1)...)
			args = append(args, v)
		}
		out = append(out, ')')
	}
	return string(out), args
}

// Compile-time assertion that pgx.ErrNoRows is reachable (helps
// reviewers find the degrade-path coupling with Store.Lookup).
var _ = pgx.ErrNoRows
