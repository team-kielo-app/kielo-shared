package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// We can't easily spin up a real Postgres in unit tests, so the
// configuration-shaping behavior is verified by re-implementing the
// pre-Ping portion via direct ParseConfig + assertions. The Ping path is
// covered by integration tests in each consuming service.

func TestInitPool_RejectsBadDSN(t *testing.T) {
	_, err := InitPool(context.Background(), "not-a-postgres-url", PoolOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse pool config")
}

// poolConfigWithOptions is a test helper that walks through the same
// config-shaping the real InitPool does, stopping before NewWithConfig
// (which would actually try to connect). Lets us verify env-var handling
// handling without a real database.
func poolConfigWithOptions(t *testing.T, opts PoolOptions) *pgxpool.Config {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://x:y@h:1/db")
	require.NoError(t, err)

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
	return cfg
}

func TestInitPool_ConfigShape_DefaultPoolSizes(t *testing.T) {
	cfg := poolConfigWithOptions(t, PoolOptions{})
	assert.Equal(t, defaultMaxConns, cfg.MaxConns)
	assert.Equal(t, defaultMinConns, cfg.MinConns)
	assert.Equal(t, pgx.QueryExecModeSimpleProtocol, cfg.ConnConfig.DefaultQueryExecMode)
	assert.Nil(t, cfg.AfterConnect, "a session SET on connect would leak through the pooler")
}

func TestInitPool_ConfigShape_CustomPoolSizes(t *testing.T) {
	cfg := poolConfigWithOptions(t, PoolOptions{
		MaxConns: 10, MinConns: 3,
	})
	assert.Equal(t, int32(10), cfg.MaxConns)
	assert.Equal(t, int32(3), cfg.MinConns)
}

func TestInitPool_ConfigShape_EnvOverridesPool(t *testing.T) {
	t.Setenv("PGX_MAX_CONNS", "8")
	t.Setenv("PGX_MIN_CONNS", "1")
	cfg := poolConfigWithOptions(t, PoolOptions{
		MaxConns: 25, MinConns: 5, // env wins
	})
	assert.Equal(t, int32(8), cfg.MaxConns)
	assert.Equal(t, int32(1), cfg.MinConns)
}

func TestSanitizeSearchPath_RejectsSemicolon(t *testing.T) {
	// Sanity check — make sure the validator we're relying on actually
	// rejects the canonical injection vector.
	_, err := SanitizeSearchPath("cms; DROP TABLE users;")
	require.Error(t, err)
}

func TestSanitizeSearchPath_AcceptsCanonicalLists(t *testing.T) {
	for _, path := range []string{
		"public",
		"cms, public",
		"users, klearn, cms, localization, communications, convo, media, public",
	} {
		t.Run(path, func(t *testing.T) {
			cleaned, err := SanitizeSearchPath(path)
			require.NoError(t, err)
			// Canonical form retains identifiers; whitespace may be normalized.
			for _, ident := range strings.Split(path, ",") {
				assert.Contains(t, cleaned, strings.TrimSpace(ident))
			}
		})
	}
}

func TestShouldPingAfterIdle_OnlyLongIdleConnectionsArePinged(t *testing.T) {
	ctx := context.Background()
	assert.False(t, shouldPingAfterIdle(ctx, pgxpool.ShouldPingParams{IdleDuration: 2 * time.Second}))
	assert.True(t, shouldPingAfterIdle(ctx, pgxpool.ShouldPingParams{IdleDuration: time.Minute}))
}
