package db

// retry.go — transient-lock retry for idempotent DB work.
//
// Postgres aborts a statement (or whole transaction) with SQLSTATE 40P01
// (deadlock_detected) or 40001 (serialization_failure) when concurrent
// transactions contend for locks in conflicting order. The abort rolls the
// failed work back, so re-running an *idempotent* operation reproduces the
// intended end state exactly once.
//
// Async, redeliverable consumers (Pub/Sub handlers, outbox drainers,
// retention/cascade workers) would otherwise surface a transient deadlock as
// an error and rely on a full redelivery round-trip to recover. These helpers
// convert that into a cheap in-process retry.
//
// Use only for idempotent operations. A single autocommit statement is always
// safe (the deadlock means nothing committed). A multi-statement transaction
// is safe iff its body is idempotent — wrap the WHOLE transaction closure
// (re-Begin on each attempt) via RetryOnDeadlock, never a partial commit.

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// deadlockRetries is the number of RETRIES (so attempts = retries+1)
	// on a transient lock error before giving up.
	deadlockRetries = 3
	// deadlockRetryBackoff is the base linear backoff between attempts
	// (attempt N waits N*backoff), spreading retries so contending
	// transactions don't immediately re-collide.
	deadlockRetryBackoff = 15 * time.Millisecond
)

// IsTransientLockError reports whether err is a Postgres deadlock (40P01) or
// serialization failure (40001) — both safe to retry for idempotent work.
func IsTransientLockError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40P01" || pgErr.Code == "40001")
}

// RetryOnDeadlock runs fn, retrying on transient lock errors (40P01/40001)
// with a short linear backoff and honoring ctx cancellation. Non-retryable
// errors (and success) return immediately.
//
// fn MUST be idempotent — see the package note. For multi-statement work, fn
// should open and commit its own transaction so each retry replays the entire
// unit (e.g. fn := func() error { return pgxsearchpath.WithTx(ctx, pool, ...) }).
func RetryOnDeadlock(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; ; attempt++ {
		err = fn()
		if err == nil || !IsTransientLockError(err) || attempt >= deadlockRetries {
			return err
		}
		log.Printf("db: transient lock error (attempt %d/%d), retrying: %v",
			attempt+1, deadlockRetries, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * deadlockRetryBackoff):
		}
	}
}

// Execer is the subset of pgx exec surface satisfied by *pgxpool.Pool and
// pgx.Tx, so ExecWithRetry works against either.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ExecWithRetry runs a single idempotent statement, retrying on transient
// lock errors. Convenience wrapper over RetryOnDeadlock for the common
// single-autocommit-statement case (e.g. an outbox MarkAsProcessed UPDATE or
// a keyed cascade DELETE).
func ExecWithRetry(ctx context.Context, q Execer, sql string, args ...any) (pgconn.CommandTag, error) {
	var tag pgconn.CommandTag
	err := RetryOnDeadlock(ctx, func() error {
		var execErr error
		tag, execErr = q.Exec(ctx, sql, args...)
		return execErr
	})
	return tag, err
}
