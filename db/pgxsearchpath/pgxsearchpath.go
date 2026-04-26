// Package pgxsearchpath provides pgx-flavored adapters for kielo-shared/db's
// per-language search_path machinery.
//
// kielo-shared/db is intentionally driver-agnostic — it expects a closure
// of the form `func(ctx, query) error` to issue SET LOCAL search_path.
// Every Kielo Go service that uses pgx ended up writing the same 5-line
// adapter inside its repository package:
//
//	func applySearchPath(ctx context.Context, tx pgx.Tx) error {
//	    exec := func(c context.Context, query string) error {
//	        _, err := tx.Exec(c, query)
//	        return err
//	    }
//	    return sharedDB.ApplySearchPathToTx(ctx, exec)
//	}
//
// This package is the single source of that adapter for pgx callers.
//
// Usage in a repository transaction:
//
//	tx, err := pool.Begin(ctx)
//	if err != nil {
//	    return err
//	}
//	defer tx.Rollback(ctx)
//	if err := pgxsearchpath.Apply(ctx, tx); err != nil {
//	    return err
//	}
//	// ... run language-scoped queries on tx ...
//	return tx.Commit(ctx)
package pgxsearchpath

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// TxBeginner is the minimal contract for anything that can start a pgx
// transaction. *pgxpool.Pool satisfies this; *pgx.Conn satisfies this.
// Tests can supply their own implementation. Defined here rather than
// importing pgxpool to keep the helper driver-agnostic at the begin
// site (the underlying type is always pgx.Tx, only the begin source
// varies).
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Apply issues SET LOCAL search_path inside the given pgx.Tx when ctx
// carries an active learning language. Mirrors sharedDB.ApplySearchPathToTx
// but accepts a pgx.Tx directly so callers don't have to write the
// closure adapter.
//
// Behavior matches the underlying helper:
//   - No-op (returns nil) when ctx has no active language.
//   - Issues SET LOCAL search_path with the standard per-language template
//     (klearn_<lang>, cms_<lang>, klearn, cms, users, localization, ...).
//   - Surfaces validation/exec failures wrapped with context.
func Apply(ctx context.Context, tx pgx.Tx) error {
	exec := func(c context.Context, query string) error {
		_, err := tx.Exec(c, query)
		return err
	}
	return sharedDB.ApplySearchPathToTx(ctx, exec)
}

// WithReadTx opens a read-only-style transaction (Begin → Apply → fn →
// Rollback), runs fn, and discards the tx unconditionally. Use for
// repository reads that need per-language search_path scoping but
// shouldn't persist anything.
//
// fn returns an error to signal "the read encountered something bad" —
// the tx is rolled back either way, but the error propagates to the
// caller. Errors from Begin / Apply are wrapped with context.
//
// Replaces the per-service `withReadTx` boilerplate that was previously
// hand-rolled in kielo-user-service / kielo-cms / kielo-content-service.
func WithReadTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgxsearchpath: begin read tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := Apply(ctx, tx); err != nil {
		return err
	}
	return fn(tx)
}

// WithTx opens a read-write transaction (Begin → Apply → fn → Commit on
// success / Rollback on error), runs fn, and commits if fn returns nil
// or rolls back if fn returns a non-nil error. Use for repository
// methods that mutate per-language tables.
//
// Errors from Begin / Apply / Commit are wrapped with context. fn's
// error is returned verbatim so callers can `errors.Is` against domain
// sentinels. If both fn and Commit succeed but the deferred Rollback
// fires (e.g. ctx cancellation between Commit return and Rollback
// scheduling) it's intentionally swallowed — pgx considers
// "rollback after successful commit" a no-op error.
func WithTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgxsearchpath: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := Apply(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgxsearchpath: commit tx: %w", err)
	}
	committed = true
	return nil
}
