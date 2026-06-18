package idempotency

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultTestDBURL = "postgres://kielo:password@localhost:5432/kielo_test?sslmode=disable"
	testStaleAfter   = 5 * time.Minute
)

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = defaultTestDBURL
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Skipf("Database not available: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("Cannot connect to database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestClaim_FirstCallAcquiresClaim(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	already, claim, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	require.NotNil(t, claim)
	require.NoError(t, claim.Fail(ctx)) // cleanup
}

func TestClaim_CompleteThenSecondCallReportsAlreadyDone(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	_, claim, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	require.NotNil(t, claim)
	require.NoError(t, claim.Complete(ctx))

	already, second, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.True(t, already)
	assert.Nil(t, second)
}

func TestClaim_FailAllowsReclaim(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	_, first, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NoError(t, first.Fail(ctx))

	already, second, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	require.NotNil(t, second)
	require.NoError(t, second.Complete(ctx))
}

func TestClaim_FreshInFlightReturnsNilClaim(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	_, first, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	require.NotNil(t, first)
	defer func() { _ = first.Fail(ctx) }()

	// Second call sees a recent processing row and refuses to take over.
	already, second, err := Claim(ctx, pool, "test.consumer", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	assert.Nil(t, second)
}

func TestClaim_StaleProcessingClaimIsTakenOver(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	// Insert a stale processing row directly (claimed_at way in the past).
	_, err := pool.Exec(ctx,
		`INSERT INTO users.processed_events (event_id, consumer, status, claimed_at, claim_id)
		 VALUES ($1, $2, 'processing', NOW() - INTERVAL '1 hour', $3)`,
		eventID, "test.consumer", uuid.New())
	require.NoError(t, err)

	already, claim, err := Claim(ctx, pool, "test.consumer", eventID, 5*time.Minute)
	require.NoError(t, err)
	assert.False(t, already)
	require.NotNil(t, claim)
	require.NoError(t, claim.Complete(ctx))
}

func TestClaim_TwoConsumersDedupIndependently(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()

	_, claimA, err := Claim(ctx, pool, "test.consumer.a", eventID, testStaleAfter)
	require.NoError(t, err)
	require.NotNil(t, claimA)
	require.NoError(t, claimA.Complete(ctx))

	_, claimB, err := Claim(ctx, pool, "test.consumer.b", eventID, testStaleAfter)
	require.NoError(t, err)
	require.NotNil(t, claimB)
	require.NoError(t, claimB.Complete(ctx))

	aRedeliver, secondA, err := Claim(ctx, pool, "test.consumer.a", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.True(t, aRedeliver)
	assert.Nil(t, secondA)

	bRedeliver, secondB, err := Claim(ctx, pool, "test.consumer.b", eventID, testStaleAfter)
	require.NoError(t, err)
	assert.True(t, bRedeliver)
	assert.Nil(t, secondB)
}

func TestClaim_EmptyKeysFallThrough(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	already, claim, err := Claim(ctx, pool, "", "evt", testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	assert.Nil(t, claim)

	already, claim, err = Claim(ctx, pool, "consumer", "", testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	assert.Nil(t, claim)
}

func TestClaim_NilPoolFallsThrough(t *testing.T) {
	already, claim, err := Claim(context.Background(), nil, "consumer", uuid.NewString(), testStaleAfter)
	require.NoError(t, err)
	assert.False(t, already)
	assert.Nil(t, claim)
}

// expireClaim ages the row's claimed_at far enough in the past to look stale.
func expireClaim(t *testing.T, pool *pgxpool.Pool, consumer, eventID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE users.processed_events
		    SET claimed_at = NOW() - INTERVAL '1 hour'
		  WHERE event_id = $1 AND consumer = $2`,
		eventID, consumer)
	require.NoError(t, err)
}

func currentClaimID(t *testing.T, pool *pgxpool.Pool, consumer, eventID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`SELECT claim_id FROM users.processed_events WHERE event_id = $1 AND consumer = $2`,
		eventID, consumer,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func currentStatus(t *testing.T, pool *pgxpool.Pool, consumer, eventID string) string {
	t.Helper()
	var s string
	err := pool.QueryRow(context.Background(),
		`SELECT status FROM users.processed_events WHERE event_id = $1 AND consumer = $2`,
		eventID, consumer,
	).Scan(&s)
	require.NoError(t, err)
	return s
}

func TestClaim_StolenClaim_ACompleteIsNoOp(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()
	consumer := "test.consumer.stolen.complete"

	_, aClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, aClaim)

	expireClaim(t, pool, consumer, eventID)

	_, bClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, bClaim)
	bID := currentClaimID(t, pool, consumer, eventID)

	// A wakes up after B took over and tries to Complete: must not clobber B.
	require.NoError(t, aClaim.Complete(ctx))

	assert.Equal(t, "processing", currentStatus(t, pool, consumer, eventID))
	assert.Equal(t, bID, currentClaimID(t, pool, consumer, eventID))

	require.NoError(t, bClaim.Complete(ctx))
	assert.Equal(t, "completed", currentStatus(t, pool, consumer, eventID))
}

func TestClaim_StolenClaim_AFailIsNoOp(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()
	consumer := "test.consumer.stolen.fail"

	_, aClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, aClaim)

	expireClaim(t, pool, consumer, eventID)

	_, bClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, bClaim)
	bID := currentClaimID(t, pool, consumer, eventID)

	// A wakes up and Fails: must not delete B's row.
	require.NoError(t, aClaim.Fail(ctx))

	assert.Equal(t, "processing", currentStatus(t, pool, consumer, eventID))
	assert.Equal(t, bID, currentClaimID(t, pool, consumer, eventID))

	require.NoError(t, bClaim.Complete(ctx))
	assert.Equal(t, "completed", currentStatus(t, pool, consumer, eventID))
}

func TestClaim_StolenClaim_BCompletesAndThirdReportsAlreadyDone(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	eventID := uuid.NewString()
	consumer := "test.consumer.stolen.lifecycle"

	_, aClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, aClaim)

	expireClaim(t, pool, consumer, eventID)

	_, bClaim, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, bClaim)

	// A's late Complete and Fail are both no-ops; B's Complete wins.
	require.NoError(t, aClaim.Complete(ctx))
	require.NoError(t, aClaim.Fail(ctx))
	require.NoError(t, bClaim.Complete(ctx))

	already, third, err := Claim(ctx, pool, consumer, eventID, 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, already)
	assert.Nil(t, third)
}
