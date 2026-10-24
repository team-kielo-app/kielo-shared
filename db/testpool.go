package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPoolConfig is the production pool config (PoolConfig) for tests, with no
// idle connections kept warm. A test that must adjust the config (a tracer,
// a pool size) starts here instead of from pgxpool.ParseConfig, so it still
// runs the service's query protocol: parameters such as []uuid.UUID, []byte
// and json.RawMessage encode under the extended protocol but fail under the
// simple one the service uses, and a test that opens its own pool hides that.
func TestPoolConfig(dataSourceName string) (*pgxpool.Config, error) {
	cfg, err := PoolConfig(dataSourceName, PoolOptions{})
	if err != nil {
		return nil, err
	}
	cfg.MinConns = 0
	return cfg, nil
}

// NewTestPool opens a pool the way InitPool does, without the startup ping, so
// a test can skip or fail on an unreachable database itself.
func NewTestPool(ctx context.Context, dataSourceName string) (*pgxpool.Pool, error) {
	cfg, err := TestPoolConfig(dataSourceName)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// ConnectTest opens one connection with the production query protocol, for
// test setup and teardown that would otherwise call pgx.Connect.
func ConnectTest(ctx context.Context, dataSourceName string) (*pgx.Conn, error) {
	cfg, err := TestPoolConfig(dataSourceName)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg.ConnConfig)
}
