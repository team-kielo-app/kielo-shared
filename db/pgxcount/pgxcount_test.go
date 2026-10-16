package pgxcount

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCounterCountsPerContext(t *testing.T) {
	pool, tracer := TestPool(t, 0)
	ctxA, a := WithCounter(context.Background())
	ctxB, b := WithCounter(context.Background())

	_, err := pool.Exec(ctxA, "SELECT 1")
	require.NoError(t, err)
	batch := &pgx.Batch{}
	batch.Queue("SELECT 1")
	batch.Queue("SELECT 2")
	require.NoError(t, pool.SendBatch(ctxB, batch).Close())
	_, err = pool.Exec(context.Background(), "SELECT 1")
	require.NoError(t, err)

	assert.EqualValues(t, 1, a.Trips())
	assert.EqualValues(t, 1, b.Trips(), "a batch is one round trip")
	assert.GreaterOrEqual(t, tracer.Total(), int64(3))
}

func TestDelayIsChargedPerRoundTrip(t *testing.T) {
	pool, _ := TestPool(t, 20*time.Millisecond)
	started := time.Now()
	_, err := pool.Exec(context.Background(), "SELECT 1")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(started), 20*time.Millisecond)
}

func TestParseBudgets(t *testing.T) {
	got := parseBudgets([]byte("# header\nme_progress: 12 # note\n\"a.b\": 3\nbad line\n"))
	assert.Equal(t, map[string]int64{"me_progress": 12, "a.b": 3}, got)
}

func TestBudgetReadsTheRegisteredFile(t *testing.T) {
	RegisterBudgets([]byte("route: 7\n"))
	assert.EqualValues(t, 7, Budget(t, "route"))
}
