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
	return sharedDB.ApplySearchPathToTx(ctx, execOn(tx))
}

// ApplyRequired is the strict variant of Apply. Use it for request
// handlers that touch migrated per-language tables and must fail when
// middleware did not attach an active learning language.
func ApplyRequired(ctx context.Context, tx pgx.Tx) error {
	return sharedDB.ApplySearchPathToTxRequired(ctx, execOn(tx))
}

func execOn(tx pgx.Tx) func(context.Context, string) error {
	return func(c context.Context, query string) error {
		_, err := tx.Exec(c, query)
		return err
	}
}

// applyFn is sharedDB.ApplySearchPathToTx or its Required variant: it
// issues the SET LOCAL (if any) through exec, so the WithReadTx / WithTx
// machinery is parameterized by strictness without duplicating the body.
type applyFn func(ctx context.Context, exec func(context.Context, string) error) error

type optionsBeginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// begin opens the transaction with its search_path. Through the pooler a
// round trip costs ~33 ms (prod, 2026-10-15), so when the beginner takes
// TxOptions (pgxpool.Pool, *pgx.Conn) BEGIN and SET LOCAL go out as one
// simple-protocol message; otherwise the SET LOCAL follows the BEGIN.
func begin(ctx context.Context, db TxBeginner, apply applyFn) (pgx.Tx, error) {
	if ob, ok := db.(optionsBeginner); ok {
		var setLocal string
		if err := apply(ctx, func(_ context.Context, query string) error {
			setLocal = query
			return nil
		}); err != nil {
			return nil, err
		}
		opts := pgx.TxOptions{}
		if setLocal != "" {
			opts.BeginQuery = "BEGIN; " + setLocal
		}
		tx, err := ob.BeginTx(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("pgxsearchpath: begin tx: %w", err)
		}
		return tx, nil
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("pgxsearchpath: begin tx: %w", err)
	}
	if err := apply(ctx, execOn(tx)); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// withReadTx is the inner read-tx body: Begin → apply → fn → Rollback
// (always). The exported wrappers parameterize it with Apply or
// ApplyRequired so the surrounding boilerplate lives in exactly one
// place rather than being duplicated for the strict variant.
func withReadTx(ctx context.Context, db TxBeginner, apply applyFn, fn func(tx pgx.Tx) error) error {
	tx, err := begin(ctx, db, apply)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return fn(tx)
}

// withTx is the inner read-write body: Begin → apply → fn → Commit on
// success / Rollback on any error. As with withReadTx, parameterized by
// the apply variant so WithTx and WithRequiredTx don't duplicate the
// commit/rollback bookkeeping.
//
// If both fn and Commit succeed but the deferred Rollback then fires
// (e.g. ctx cancellation between Commit return and Rollback scheduling)
// the rollback error is intentionally swallowed — pgx considers
// "rollback after successful commit" a no-op error.
func withTx(ctx context.Context, db TxBeginner, apply applyFn, fn func(tx pgx.Tx) error) error {
	tx, err := begin(ctx, db, apply)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgxsearchpath: commit tx: %w", err)
	}
	committed = true
	return nil
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
	return withReadTx(ctx, db, sharedDB.ApplySearchPathToTx, fn)
}

// WithRequiredReadTx is the strict variant of WithReadTx. It returns
// ErrNoActiveLanguage (wrapped) and does not run fn when ctx has no
// active learning language.
func WithRequiredReadTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) error {
	return withReadTx(ctx, db, sharedDB.ApplySearchPathToTxRequired, fn)
}

// WithTx opens a read-write transaction (Begin → Apply → fn → Commit on
// success / Rollback on error), runs fn, and commits if fn returns nil
// or rolls back if fn returns a non-nil error. Use for repository
// methods that mutate per-language tables.
//
// Errors from Begin / Apply / Commit are wrapped with context. fn's
// error is returned verbatim so callers can `errors.Is` against domain
// sentinels.
func WithTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) error {
	return withTx(ctx, db, sharedDB.ApplySearchPathToTx, fn)
}

// WithRequiredTx is the strict variant of WithTx. It returns
// ErrNoActiveLanguage (wrapped) and does not run fn when ctx has no
// active learning language.
func WithRequiredTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) error {
	return withTx(ctx, db, sharedDB.ApplySearchPathToTxRequired, fn)
}
