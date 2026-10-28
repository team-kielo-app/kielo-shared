package learnerintent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	shareddb "github.com/team-kielo-app/kielo-shared/db"
)

type fakeRows struct {
	pgx.Rows
	data [][]any
	pos  int
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.data) }
func (r *fakeRows) Close()     {}
func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}
func (r *fakeRows) Scan(dest ...any) error {
	row := r.data[r.pos-1]
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = row[i].(string)
		case **string:
			if v, ok := row[i].(string); ok {
				*p = &v
			}
		case **time.Time:
			if v, ok := row[i].(time.Time); ok {
				*p = &v
			}
		case **int32:
			if v, ok := row[i].(int32); ok {
				*p = &v
			}
		}
	}
	return nil
}

type fakeQuerier struct {
	calls [][]any
	sqls  []string
	reply func(ids []string) [][]any
	err   error
}

func (f *fakeQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.sqls = append(f.sqls, sql)
	f.calls = append(f.calls, args)
	if f.err != nil {
		return nil, f.err
	}
	return &fakeRows{data: f.reply(args[0].([]string))}, nil
}

func TestLoadSQLShape(t *testing.T) {
	sql := strings.Join(strings.Fields(LoadSQL), " ")
	assert.Contains(t, sql, "LEFT JOIN users.feature_usage f")
	assert.Contains(t, sql, "LEFT JOIN users.users u")
	assert.Contains(t, sql, "u.learning_reason")
	assert.Contains(t, sql, "unnest($1::text[])")
	assert.Contains(t, sql, "f.period_start >= $2::date")
	assert.Contains(t, sql, "f.feature = ANY($3::text[])")
}

func TestLoadOneQueryWithResolverFeaturesAndWindow(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	q := &fakeQuerier{reply: func(ids []string) [][]any {
		return [][]any{
			{a.String(), "work", FeatureReading, day(1), int32(25)},
			{a.String(), "work", FeatureVisit, day(1), int32(6)},
			{b.String(), nil, nil, nil, nil},
		}
	}}
	got, err := Load(context.Background(), q, []uuid.UUID{a, b, a}, now)
	require.NoError(t, err)
	require.Len(t, q.calls, 1)
	assert.Equal(t, []string{a.String(), b.String()}, q.calls[0][0])
	assert.Equal(t, "2026-08-30", q.calls[0][1])
	assert.Equal(t, Features(), q.calls[0][2])

	require.Len(t, got, 2)
	assert.Equal(t, "work", got[a].Goal)
	assert.Equal(t, TypeReading, got[a].TopType)
	assert.Equal(t, SessionLong, got[a].SessionLen)
	assert.Equal(t, SourceColdStart, got[b].Sources["type_minutes"])
	assert.Equal(t, "", got[b].Goal)
}

func TestLoadAbsentUserStillGetsColdStartProfile(t *testing.T) {
	id := uuid.New()
	q := &fakeQuerier{reply: func([]string) [][]any { return nil }}
	got, err := Load(context.Background(), q, []uuid.UUID{id}, now)
	require.NoError(t, err)
	assert.Equal(t, SourceColdStart, got[id].Sources["goal"])
}

func TestLoadChunksLargeBatches(t *testing.T) {
	ids := make([]uuid.UUID, 2500)
	for i := range ids {
		ids[i] = uuid.New()
	}
	q := &fakeQuerier{reply: func([]string) [][]any { return nil }}
	got, err := Load(context.Background(), q, ids, now)
	require.NoError(t, err)
	assert.Len(t, got, 2500)
	require.Len(t, q.calls, 3)
	assert.Len(t, q.calls[0][0], LoadChunk)
	assert.Len(t, q.calls[2][0], 500)
}

func TestLoadNoIDsRunsNoQuery(t *testing.T) {
	q := &fakeQuerier{}
	got, err := Load(context.Background(), q, nil, now)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Empty(t, q.calls)
}

func TestLoadPropagatesQueryError(t *testing.T) {
	q := &fakeQuerier{err: errors.New("boom")}
	_, err := Load(context.Background(), q, []uuid.UUID{uuid.New()}, now)
	require.ErrorContains(t, err, "boom")
}

func TestLoadAgainstDatabase(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL environment variable is required")
	}
	ctx := context.Background()
	pool, err := shareddb.NewTestPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	id, missing := uuid.New(), uuid.New()
	today := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO users.users (id, email, learning_reason) VALUES ($1, $2, 'work')`,
		id.String(), "intent-"+id.String()[:8]+"@example.test")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO users.feature_usage (user_id, feature, period_start, usage_count)
		VALUES ($1, 'time_spent:reading', $2::date, 30), ($1, 'time_spent:visit', $2::date, 8),
		       ($1, 'words_viewed', $2::date, 99), ($1, 'time_spent:reading', $2::date - 400, 500)`,
		id.String(), today.Format("2006-01-02"))
	require.NoError(t, err)

	got, err := Load(ctx, tx, []uuid.UUID{id, missing}, today)
	require.NoError(t, err)
	assert.Equal(t, "work", got[id].Goal)
	assert.InDelta(t, 30, got[id].TypeMinutes[TypeReading], 1e-9)
	assert.Equal(t, 1, got[id].ActiveDays)
	assert.Equal(t, SourceColdStart, got[missing].Sources["goal"])
}
