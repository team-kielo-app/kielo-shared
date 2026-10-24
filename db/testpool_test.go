package db

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestPoolConfig_IsTheProductionPoolConfig(t *testing.T) {
	prod, err := PoolConfig("postgres://x:y@h:1/db", PoolOptions{})
	require.NoError(t, err)
	test, err := TestPoolConfig("postgres://x:y@h:1/db")
	require.NoError(t, err)

	assert.Equal(t, pgx.QueryExecModeSimpleProtocol, test.ConnConfig.DefaultQueryExecMode)
	assert.Equal(t, prod.ConnConfig.DefaultQueryExecMode, test.ConnConfig.DefaultQueryExecMode)
	assert.Equal(t, prod.MaxConns, test.MaxConns)
	assert.Equal(t, prod.ConnConfig.ConnectTimeout, test.ConnConfig.ConnectTimeout)
	assert.NotNil(t, test.ShouldPing)
	assert.NotNil(t, test.ConnConfig.DialFunc)
	assert.Nil(t, test.AfterConnect)
	assert.Zero(t, test.MinConns)
}

func TestTestPoolConfig_RejectsBadDSN(t *testing.T) {
	_, err := TestPoolConfig("not-a-postgres-url")
	require.Error(t, err)
}
