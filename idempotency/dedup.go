package idempotency

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadyProcessed signals that the (eventID, consumer) pair was already handled.
// Callers should treat this as success (idempotent ack) and skip processing.
var ErrAlreadyProcessed = errors.New("idempotency: event already processed")

// ClaimToken represents an in-flight processing slot. Callers must call
// exactly one of Complete (on success) or Fail (on error) before returning.
type ClaimToken struct {
	db       *pgxpool.Pool
	consumer string
	eventID  string
	claimID  uuid.UUID
}

// Claim attempts to acquire a processing slot for (consumer, eventID).
//
// Returns:
//   - alreadyDone=true, claim=nil, err=nil: previously completed; skip work and ack.
//   - alreadyDone=false, claim!=nil, err=nil: claim acquired; caller MUST call
//     Complete on success or Fail on error.
//   - alreadyDone=false, claim=nil, err=nil: another worker holds a fresh
//     in-flight claim; caller should NACK so Pub/Sub retries later.
//   - err != nil: DB failure; caller should NACK.
//
// If a stale 'processing' row exists (older than staleAfter), Claim takes it over
// and stamps a fresh claim_id; the prior worker's Complete/Fail will become a no-op.
// Empty eventID/consumer or a nil pool returns (false, nil, nil) so callers
// without dedup configured fall through to the legacy non-idempotent path.
func Claim(
	ctx context.Context,
	db *pgxpool.Pool,
	consumer, eventID string,
	staleAfter time.Duration,
) (alreadyDone bool, claim *ClaimToken, err error) {
	if db == nil || eventID == "" || consumer == "" {
		return false, nil, nil
	}
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}

	// Use Postgres interval text so we don't depend on pgx's time.Duration
	// codec for INTERVAL parameters.
	staleInterval := fmt.Sprintf("%d milliseconds", staleAfter.Milliseconds())

	newClaimID := uuid.New()

	const q = `
INSERT INTO users.processed_events (event_id, consumer, status, claimed_at, claim_id)
     VALUES ($1, $2, 'processing', NOW(), $4)
ON CONFLICT (event_id, consumer) DO UPDATE
   SET status = 'processing', claimed_at = NOW(), claim_id = $4
   WHERE users.processed_events.status = 'failed'
      OR (users.processed_events.status = 'processing'
          AND users.processed_events.claimed_at < NOW() - $3::interval)
RETURNING claim_id, status
`

	var rowClaimID uuid.UUID
	var status string
	scanErr := db.QueryRow(ctx, q, eventID, consumer, staleInterval, newClaimID).Scan(&rowClaimID, &status)
	if scanErr == nil {
		if rowClaimID != newClaimID {
			// Another worker already owns a fresh row; the upsert was a no-op
			// that returned the existing row. Treat by status.
			if status == "completed" {
				return true, nil, nil
			}
			return false, nil, nil
		}
		return false, &ClaimToken{db: db, consumer: consumer, eventID: eventID, claimID: newClaimID}, nil
	}
	if !errors.Is(scanErr, pgx.ErrNoRows) {
		return false, nil, scanErr
	}

	// Conflict + WHERE rejected the update. Inspect the existing row to
	// distinguish "already completed" from "fresh in-flight by another worker".
	var existingStatus string
	lookupErr := db.QueryRow(ctx,
		`SELECT status FROM users.processed_events WHERE event_id = $1 AND consumer = $2`,
		eventID, consumer,
	).Scan(&existingStatus)
	if lookupErr != nil {
		return false, nil, lookupErr
	}
	switch existingStatus {
	case "completed":
		return true, nil, nil
	case "processing":
		return false, nil, nil
	default:
		return false, nil, nil
	}
}

// Complete marks the claim as completed. Call this AFTER the side effect succeeds.
// If the row's claim_id no longer matches (another worker took over a stale claim),
// the update is a no-op and we log a warning — the side effect already succeeded;
// the dedup row simply isn't ours to clean up.
func (c *ClaimToken) Complete(ctx context.Context) error {
	if c == nil || c.db == nil {
		return nil
	}
	tag, err := c.db.Exec(ctx,
		`UPDATE users.processed_events
		    SET status = 'completed', claimed_at = NULL, processed_at = NOW()
		  WHERE event_id = $1 AND consumer = $2 AND claim_id = $3`,
		c.eventID, c.consumer, c.claimID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		slog.WarnContext(ctx, "idempotency: claim was stolen — another worker took over",
			"consumer", c.consumer, "event_id", c.eventID, "claim_id", c.claimID.String())
	}
	return nil
}

// Fail removes the claim row so the next retry can re-attempt the side effect.
// Call this on side-effect failure. If the row's claim_id no longer matches
// (another worker took over), the delete is a no-op and we log a warning.
func (c *ClaimToken) Fail(ctx context.Context) error {
	if c == nil || c.db == nil {
		return nil
	}
	tag, err := c.db.Exec(ctx,
		`DELETE FROM users.processed_events
		  WHERE event_id = $1 AND consumer = $2 AND claim_id = $3 AND status = 'processing'`,
		c.eventID, c.consumer, c.claimID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		slog.WarnContext(ctx, "idempotency: claim was stolen — another worker took over",
			"consumer", c.consumer, "event_id", c.eventID, "claim_id", c.claimID.String())
	}
	return nil
}
