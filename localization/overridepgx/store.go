// Package overridepgx is the pgx-backed implementation of
// localization.OverrideStore. Reads admin-approved translations from
// localization.dynamic_translations.
//
// Lives in its own sub-package so consumers that only need
// Noop/MapOverrideStore don't pull pgx transitively into their
// binaries. Mirrors cacheredis's "adapter, not a client" stance:
// callers supply their own pgxpool.Pool; this package owns the SQL.
package overridepgx

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/team-kielo-app/kielo-shared/localization"
)

// Store adapts a pgxpool.Pool to localization.OverrideStore. Lookups
// hit localization.dynamic_translations with the seam's read priority:
//  1. status='override'  (admin replaced the machine translation)
//  2. status='approved'  (admin confirmed the machine translation)
//  3. nothing — falls through to cache + provider chain.
//
// Stale rows (stored source_version != requested) are filtered server-side
// by the WHERE clause. The seam never sees them. The Reaper (reaper.go)
// is the periodic background job that flips stale rows to
// status='pending_review' so admin-ui's audit queue surfaces them; it
// runs out-of-band on the caller's scheduler (Cloud Scheduler, k8s
// CronJob, in-process ticker — wiring is the caller's choice).
type Store struct {
	pool *pgxpool.Pool
}

// New wraps a pgxpool.Pool as a localization.OverrideStore.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// lookupQuery is the single read path for OverrideStore.Lookup.
//
// Index plan: this query is served by the UNIQUE constraint
// (resource_type, resource_id, source_version, language_code) — one
// btree probe, no scan. Status filter is in-row.
//
// ORDER BY ranks 'override' above 'approved' so admin edits win when
// somehow both exist for the same key (shouldn't happen given the
// unique constraint, but the rank makes the intent explicit).
const lookupQuery = `
	SELECT translated_text
	  FROM localization.dynamic_translations
	 WHERE resource_type   = $1
	   AND resource_id     = $2
	   AND source_version  = $3
	   AND language_code   = $4
	   AND status         IN ('override', 'approved')
	 ORDER BY CASE status WHEN 'override' THEN 0 ELSE 1 END
	 LIMIT 1
`

// Lookup implements localization.OverrideStore.
//
// Returns ("", false) on:
//   - no matching row (most common path; seam falls through to cache)
//   - pgx error (Redis-style degrade: rather than erroring the request,
//     pretend no override and let the provider chain handle it)
//   - context cancellation
//
// Compile-time check: this method makes *Store satisfy the
// localization.OverrideStore interface.
func (s *Store) Lookup(
	ctx context.Context,
	namespace, sourceID, sourceVersion, targetLocale string,
) (string, bool) {
	if s == nil || s.pool == nil {
		return "", false
	}

	var value string
	err := s.pool.QueryRow(ctx, lookupQuery, namespace, sourceID, sourceVersion, targetLocale).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false
		}
		// Don't propagate the error — degrade gracefully. The seam's
		// metrics counter will record this as a "no override found"
		// from the caller's perspective; the seam's downstream provider
		// call will record the actual translation path used.
		return "", false
	}
	return value, true
}

// Compile-time assertion that *Store satisfies the interface.
var _ localization.OverrideStore = (*Store)(nil)

// batchLookupQuery is the single composite-tuple read path for
// BatchLookup. Sweep TTTT-B: one SQL round-trip serves N refs via the
// `(resource_type, resource_id, source_version) IN (VALUES ...)` clause.
//
// Index plan: every row in the IN-list still hits the canonical
// (resource_type, resource_id, source_version, language_code) UNIQUE
// btree probe. Total cost is O(N log M) where M = table size, vs the
// pre-TTTT O(N × log M × RTT) when each ref made its own QueryRow.
//
// The composite VALUES list is built with pgx's $N parameter packing
// — 4 params per ref (type, id, version, +1 for language_code shared
// across all refs). For N=264 (the scenario list case) that's 793
// params + 1 language_code = under pgx's 65535-parameter limit by
// orders of magnitude.
const batchLookupQuery = `
	SELECT resource_type, resource_id, source_version, translated_text
	  FROM localization.dynamic_translations
	 WHERE language_code = $1
	   AND status        IN ('override', 'approved')
	   AND (resource_type, resource_id, source_version) IN (%s)
	 ORDER BY CASE status WHEN 'override' THEN 0 ELSE 1 END
`

// BatchLookup implements localization.BatchOverrideStore. Issues ONE
// SQL query for N refs. Returns a map keyed by
// OverrideBatchKey(namespace, sourceID, sourceVersion) → translated
// value for every (namespace, id, version) tuple that matched. Misses
// are omitted from the map (callers check map-presence).
//
// On any DB error, returns the partial map + the error so the seam's
// fallback chain can decide whether to retry per-ref or skip overrides
// entirely. The seam currently treats batch-lookup errors as
// "no overrides" and falls through to cache + provider, mirroring the
// graceful-degrade contract of the per-row Lookup.
func (s *Store) BatchLookup(
	ctx context.Context,
	refs []localization.OverrideRef,
	targetLocale string,
) (map[string]string, error) {
	out := make(map[string]string)
	if s == nil || s.pool == nil || len(refs) == 0 {
		return out, nil
	}
	// Build the (resource_type, resource_id, source_version) tuple list.
	// pgx supports row-value IN constructs via the standard
	// `($N, $N+1, $N+2)` syntax inside a parenthesized list. We build
	// the SQL with placeholder text + args slice that matches.
	args := make([]any, 0, 1+len(refs)*3)
	args = append(args, targetLocale)
	// Build the VALUES portion: "($2, $3, $4), ($5, $6, $7), ..."
	tuples := make([]byte, 0, len(refs)*16)
	for i, ref := range refs {
		if i > 0 {
			tuples = append(tuples, ',')
		}
		base := 2 + i*3
		tuples = append(tuples, '(')
		tuples = appendPlaceholder(tuples, base)
		tuples = append(tuples, ',')
		tuples = appendPlaceholder(tuples, base+1)
		tuples = append(tuples, ',')
		tuples = appendPlaceholder(tuples, base+2)
		tuples = append(tuples, ')')
		args = append(args, ref.Namespace, ref.SourceID, ref.SourceVersion)
	}
	query := formatBatchLookupQuery(string(tuples))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var ns, id, ver, val string
		if err := rows.Scan(&ns, &id, &ver, &val); err != nil {
			return out, err
		}
		out[localization.OverrideBatchKey(ns, id, ver)] = val
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// appendPlaceholder writes "$N" to dst without an intermediate
// fmt.Sprintf allocation. Keeps the hot path allocation-free.
func appendPlaceholder(dst []byte, n int) []byte {
	dst = append(dst, '$')
	// itoa: assumes 1 ≤ n ≤ 99999 (4 places). Plenty for the 65535-
	// parameter pgx ceiling.
	if n < 10 {
		return append(dst, byte('0'+n))
	}
	if n < 100 {
		return append(dst, byte('0'+n/10), byte('0'+n%10))
	}
	if n < 1000 {
		return append(dst, byte('0'+n/100), byte('0'+(n/10)%10), byte('0'+n%10))
	}
	if n < 10000 {
		return append(dst,
			byte('0'+n/1000),
			byte('0'+(n/100)%10),
			byte('0'+(n/10)%10),
			byte('0'+n%10))
	}
	return append(dst,
		byte('0'+n/10000),
		byte('0'+(n/1000)%10),
		byte('0'+(n/100)%10),
		byte('0'+(n/10)%10),
		byte('0'+n%10))
}

// formatBatchLookupQuery splices the tuple-list into the query template
// once at runtime. The composite tuple list shape can't be
// parameterized as a single placeholder; the only thing the literal
// embeds is the placeholder-index list, no user data, so this is
// SQL-injection-safe.
func formatBatchLookupQuery(tuples string) string {
	// fmt.Sprintf-equivalent without the alloc. Append-only.
	out := make([]byte, 0, len(batchLookupQuery)+len(tuples))
	for i := 0; i < len(batchLookupQuery); i++ {
		if batchLookupQuery[i] == '%' && i+1 < len(batchLookupQuery) && batchLookupQuery[i+1] == 's' {
			out = append(out, tuples...)
			i++
			continue
		}
		out = append(out, batchLookupQuery[i])
	}
	return string(out)
}

// Compile-time assertion that *Store satisfies BatchOverrideStore.
var _ localization.BatchOverrideStore = (*Store)(nil)
