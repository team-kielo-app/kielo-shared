package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions configures the pgxpool created by InitPool. Zero values
// pick the platform-standard defaults; only override when the service
// has a documented reason (e.g. constrained Cloud Run sidecars).
type PoolOptions struct {
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

// pingAfterIdle is how long a pooled connection may sit unused before it is
// pinged on acquire. pgx's default (1 s) pinged almost every acquire in a
// low-traffic service, one extra pooler round trip (~33 ms) per request;
// TCP keepalives (dial.go) already catch a peer that went away.
const pingAfterIdle = 30 * time.Second

func shouldPingAfterIdle(_ context.Context, params pgxpool.ShouldPingParams) bool {
	return params.IdleDuration > pingAfterIdle
}

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
//   - A 5 s connect timeout (unless the DSN sets connect_timeout), TCP
//     keepalives and TCP_USER_TIMEOUT (dial.go), so a stalled network path
//     fails queries in seconds instead of holding requests for minutes.
//   - No connection-level search_path. Behind the transaction-mode pooler a
//     session SET lands on whichever backend is free and stays there for the
//     next client; per-language scoping is SET LOCAL inside each transaction.
//   - Ping verification before returning so a misconfigured DSN fails
//     loudly at startup rather than at the first query.
//
// Replaces the verbatim 30-line InitDB / NewPool helpers that lived in
// every service's internal/db/db.go. Centralizes the pgx defaults so
// platform-wide tunings (PgBouncer compatibility, pool sizing) only
// need updating in one place.
func InitPool(ctx context.Context, dataSourceName string, opts PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := PoolConfig(dataSourceName, opts)
	if err != nil {
		return nil, err
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

// PoolConfig builds the pgxpool config InitPool opens a pool with: pool sizes,
// the simple query protocol, ping policy, connect timeout and dialer. It is
// the one definition of the service's pool, so a test pool built from it
// (TestPoolConfig) cannot drift from production.
func PoolConfig(dataSourceName string, opts PoolOptions) (*pgxpool.Config, error) {
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
	cfg.MinConns = EnvNonNegInt32("PGX_MIN_CONNS", minFallback)

	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.ShouldPing = shouldPingAfterIdle

	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = connectTimeout
	}
	cfg.ConnConfig.DialFunc = newDialer().DialContext
	return cfg, nil
}
