package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplicaDSN_PlanetScaleUsesTheDirectPortAndTheReplicaUser(t *testing.T) {
	got, err := ReplicaDSN("postgresql://pscale_api_abc.xyz:pw@eu-west1-1.horizon.psdb.cloud:6432/postgres?sslmode=verify-full")
	require.NoError(t, err)
	assert.Equal(t, "postgresql://pscale_api_abc.xyz%7Creplica:pw@eu-west1-1.horizon.psdb.cloud:5432/postgres?sslmode=verify-full", got)

	cfg, err := pgxpool.ParseConfig(got) // prodpool:ok parses the DSN, never connects
	require.NoError(t, err)
	assert.Equal(t, "pscale_api_abc.xyz|replica", cfg.ConnConfig.User)
	assert.Equal(t, uint16(5432), cfg.ConnConfig.Port)
}

func TestReplicaDSN_IsNotAppliedTwice(t *testing.T) {
	got, err := ReplicaDSN("postgres://u%7Creplica:pw@db.psdb.cloud:5432/postgres")
	require.NoError(t, err)
	assert.Equal(t, "postgres://u%7Creplica:pw@db.psdb.cloud:5432/postgres", got)
}

func TestReplicaDSN_OtherHostsHaveNoReplicaRoute(t *testing.T) {
	for _, dsn := range []string{
		"postgresql://kielo:password@postgres:5432/kielo_test?sslmode=disable",
		"postgresql://kielo:password@127.0.0.1:5432/kielo_test",
		"host=db.psdb.cloud user=u password=p dbname=postgres",
		"",
	} {
		_, err := ReplicaDSN(dsn)
		assert.Error(t, err, dsn)
	}
}

func TestReplicaDSN_AnExplicitURLWins(t *testing.T) {
	t.Setenv("DATABASE_REPLICA_URL", "postgresql://r:pw@replica.internal:5432/postgres")
	got, err := ReplicaDSN("postgresql://kielo:password@postgres:5432/kielo_test")
	require.NoError(t, err)
	assert.Equal(t, "postgresql://r:pw@replica.internal:5432/postgres", got)
}

func lazyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://x:y@127.0.0.1:1/db") // prodpool:ok closed DSN, the pool never dials
	require.NoError(t, err)
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestNewReader_StaysOnThePrimaryUnlessSwitchedOn(t *testing.T) {
	primary := lazyPool(t)
	r := NewReader(primary, "postgresql://u:pw@db.psdb.cloud:6432/postgres")
	assert.Same(t, primary, r.Pool(context.Background()))
	assert.False(t, r.OnReplica(context.Background()))
}

func TestNewReader_StaysOnThePrimaryWhereThereIsNoReplica(t *testing.T) {
	t.Setenv("DB_REPLICA_READS", "on")
	primary := lazyPool(t)
	r := NewReader(primary, "postgresql://kielo:password@postgres:5432/kielo_test")
	assert.Same(t, primary, r.Pool(context.Background()))
}

func TestNewReader_OpensASmallReplicaPoolWithNoIdleConnections(t *testing.T) {
	t.Setenv("DB_REPLICA_READS", "on")
	t.Setenv("PGX_MAX_CONNS", "25")
	r := NewReader(lazyPool(t), "postgresql://u:pw@db.psdb.cloud:6432/postgres")
	t.Cleanup(r.Close)
	require.NotNil(t, r.replica)
	cfg := r.replica.Config()
	assert.Equal(t, defaultReplicaMaxConns, cfg.MaxConns, "the primary's pool size must not carry over")
	assert.Equal(t, int32(0), cfg.MinConns)
	assert.Equal(t, "u|replica", cfg.ConnConfig.User)
	assert.Equal(t, uint16(5432), cfg.ConnConfig.Port)
}

func readerWithProbe(t *testing.T, probe func(context.Context) (time.Duration, error)) (*Reader, *time.Time) {
	t.Helper()
	clock := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	r := &Reader{
		primary: lazyPool(t),
		replica: lazyPool(t),
		maxLag:  defaultReplicaMaxLag,
		now:     func() time.Time { return clock },
		probe:   probe,
	}
	return r, &clock
}

func TestReader_ReadsFromAReplicaThatAnswersWithinTheLagLimit(t *testing.T) {
	r, _ := readerWithProbe(t, func(context.Context) (time.Duration, error) { return 2 * time.Second, nil })
	assert.Same(t, r.replica, r.Pool(context.Background()))
	assert.True(t, r.OnReplica(context.Background()))
}

func TestReader_FallsBackWhenTheReplicaIsTooFarBehindOrDown(t *testing.T) {
	behind, _ := readerWithProbe(t, func(context.Context) (time.Duration, error) { return 45 * time.Second, nil })
	assert.Same(t, behind.primary, behind.Pool(context.Background()))

	down, _ := readerWithProbe(t, func(context.Context) (time.Duration, error) { return 0, errors.New("connection refused") })
	assert.Same(t, down.primary, down.Pool(context.Background()))
}

func TestReader_AsksTheReplicaAtMostOncePerInterval_AndRecovers(t *testing.T) {
	calls := 0
	lag := 45 * time.Second
	r, clock := readerWithProbe(t, func(context.Context) (time.Duration, error) {
		calls++
		return lag, nil
	})
	ctx := context.Background()
	assert.Same(t, r.primary, r.Pool(ctx))
	assert.Same(t, r.primary, r.Pool(ctx))
	assert.Equal(t, 1, calls)

	lag = time.Second
	*clock = clock.Add(replicaRecheckEvery + time.Second)
	assert.Same(t, r.replica, r.Pool(ctx))
	assert.Equal(t, 2, calls)
}

func TestReader_ACancelledRequestDoesNotTurnTheReplicaOff(t *testing.T) {
	r, _ := readerWithProbe(t, func(ctx context.Context) (time.Duration, error) { return 0, ctx.Err() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Same(t, r.replica, r.Pool(ctx))
}

func TestReader_NilAndClose(t *testing.T) {
	var r *Reader
	assert.Nil(t, r.Pool(context.Background()))
	r.Close()
}

// A read-only repository holds this where it held a pool.
type readQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var (
	_ readQuerier = (*Reader)(nil)
	_ readQuerier = (*pgxpool.Pool)(nil)
)
