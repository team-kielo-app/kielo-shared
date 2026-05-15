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
// by the WHERE clause. The seam never sees them. A separate background
// task (out of scope here) reaps stale rows by flipping their status to
// 'pending_review' so admin-ui's audit queue surfaces them.
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
