package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions configures the pgxpool created by InitPool. Zero values
// pick the platform-standard defaults; only override when the service
// has a documented reason (e.g. constrained Cloud Run sidecars).
type PoolOptions struct {
	// SearchPath is the connection-level search_path applied via the
	// pgxpool AfterConnect hook. Empty disables the hook (caller still
	// gets the pool's default search_path or whatever pgx parses from
	// the DSN). Use a comma-separated list, e.g. "cms, public, klearn".
	SearchPath string

	// MaxConns / MinConns override the platform defaults (25 / 2). The
	// PGX_MAX_CONNS / PGX_MIN_CONNS env vars override these in turn.
	// Leaving these zero-valued means the env vars (if set) win, then
	// fall through to 25 / 2.
	MaxConns int32
	MinConns int32
}

// Default pool sizes — chosen for a single Cloud Run instance servicing
// concurrent fan-out queries (the default pgx MaxConns of 4 starves
// any handler that runs more than a couple of queries in parallel).
const (
	defaultMaxConns int32 = 25
	defaultMinConns int32 = 2
)

// InitPool creates a pgx pool with the platform-standard configuration:
//
//   - MaxConns / MinConns from PGX_MAX_CONNS / PGX_MIN_CONNS env vars
//     (default 25 / 2). Per-service overrides via opts.MaxConns /
//     opts.MinConns are applied as the fallback when the env var isn't
//     set.
//   - DefaultQueryExecMode set to QueryExecModeSimpleProtocol — required
//     for compatibility with PgBouncer transaction pooling and Neon's
//     poolers, which reject prepared statement caching across pooled
//     connections ("prepared statement is already in use" errors).
//   - AfterConnect hook applying opts.SearchPath via pgxsearchpath
//     (only when SearchPath is non-empty). Per-language scoping is
//     applied per-transaction via SET LOCAL search_path on top.
//   - Ping verification before returning so a misconfigured DSN fails
//     loudly at startup rather than at the first query.
//
// Replaces the verbatim 30-line InitDB / NewPool helpers that lived in
// every service's internal/db/db.go. Centralizes the pgx defaults so
// platform-wide tunings (PgBouncer compatibility, pool sizing) only
// need updating in one place.
func InitPool(ctx context.Context, dataSourceName string, opts PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	maxFallback := opts.MaxConns
	if maxFallback <= 0 {
		maxFallback = defaultMaxConns
	}
	minFallback := opts.MinConns
	if minFallback <= 0 {
		minFallback = defaultMinConns
	}
	cfg.MaxConns = EnvInt32("PGX_MAX_CONNS", maxFallback)
	cfg.MinConns = EnvInt32("PGX_MIN_CONNS", minFallback)

	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	if opts.SearchPath != "" {
		cleaned, err := SanitizeSearchPath(opts.SearchPath)
		if err != nil {
			return nil, fmt.Errorf("invalid search_path %q: %w", opts.SearchPath, err)
		}
		stmt := "SET search_path TO " + cleaned
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, stmt)
			return err
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
