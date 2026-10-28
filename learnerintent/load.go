package learnerintent

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Querier is the pgx surface Load needs; *pgxpool.Pool, *pgx.Conn and pgx.Tx
// satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadChunk is how many users one query covers.
const LoadChunk = 1000

// LoadSQL returns one row per requested user and feature row (a user with no
// rows, or absent from users.users, still yields one row with NULLs). Ids and
// features travel as text arrays and the window start as a date string so the
// statement also runs under pgx's simple protocol.
const LoadSQL = `
SELECT ids.id::text, u.learning_reason, f.feature, f.period_start, f.usage_count
FROM unnest($1::text[]) AS ids(id)
LEFT JOIN users.users u ON u.id = ids.id::uuid
LEFT JOIN users.feature_usage f
  ON f.user_id = ids.id::uuid
 AND f.period_start >= $2::date
 AND f.feature = ANY($3::text[])`

// Load returns a Profile for every id, using the default window. Learners with
// no usage or no users.users row get a cold_start profile.
func Load(ctx context.Context, q Querier, userIDs []uuid.UUID, now time.Time) (map[uuid.UUID]Profile, error) {
	out := make(map[uuid.UUID]Profile, len(userIDs))
	seen := make(map[uuid.UUID]struct{}, len(userIDs))
	unique := make([]uuid.UUID, 0, len(userIDs))
	for _, id := range userIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	for start := 0; start < len(unique); start += LoadChunk {
		end := min(start+LoadChunk, len(unique))
		if err := loadChunk(ctx, q, unique[start:end], now, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func loadChunk(ctx context.Context, q Querier, ids []uuid.UUID, now time.Time, out map[uuid.UUID]Profile) error {
	idText := make([]string, len(ids))
	for i, id := range ids {
		idText[i] = id.String()
	}
	startDay := WindowStart(now, DefaultWindowDays).Format("2006-01-02")
	rows, err := q.Query(ctx, LoadSQL, idText, startDay, Features())
	if err != nil {
		return fmt.Errorf("learnerintent: query: %w", err)
	}
	defer rows.Close()

	goals := make(map[uuid.UUID]string, len(ids))
	usage := make(map[uuid.UUID][]UsageRow, len(ids))
	for rows.Next() {
		var (
			idStr   string
			goal    *string
			feature *string
			period  *time.Time
			count   *int32
		)
		if err := rows.Scan(&idStr, &goal, &feature, &period, &count); err != nil {
			return fmt.Errorf("learnerintent: scan: %w", err)
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return fmt.Errorf("learnerintent: bad id %q: %w", idStr, err)
		}
		if goal != nil {
			goals[id] = *goal
		}
		if feature != nil && period != nil && count != nil {
			usage[id] = append(usage[id], UsageRow{Feature: *feature, PeriodStart: *period, UsageCount: int(*count)})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("learnerintent: rows: %w", err)
	}
	for _, id := range ids {
		out[id] = Resolve(goals[id], usage[id], now, DefaultWindowDays)
	}
	return nil
}
