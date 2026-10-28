package learnerlevel

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

func (r *fakeRows) Next() bool                    { r.pos++; return r.pos <= len(r.data) }
func (r *fakeRows) Close()                        {}
func (r *fakeRows) Err() error                    { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
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
		case **float64:
			if v, ok := row[i].(float64); ok {
				*p = &v
			}
		case **time.Time:
			if v, ok := row[i].(time.Time); ok {
				*p = &v
			}
		}
	}
	return nil
}

type fakeQuerier struct {
	sqls  []string
	calls [][]any
	reply func(sql string, ids []string) [][]any
	errs  []error
}

func (f *fakeQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.sqls = append(f.sqls, sql)
	f.calls = append(f.calls, args)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	return &fakeRows{data: f.reply(sql, args[0].([]string))}, nil
}

var loadNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func TestLoadSQLShape(t *testing.T) {
	sql := strings.Join(strings.Fields(LoadSQL), " ")
	assert.Contains(t, sql, "unnest($1::text[])")
	assert.Contains(t, sql, "LEFT JOIN users.users u")
	assert.Contains(t, sql, "users.learner_language_levels")
	assert.Contains(t, sql, "u.estimated_skill_level")
	assert.Contains(t, sql, "LEFT JOIN klearn.learner_profiles lp")
	assert.Contains(t, sql, "lp.learning_language_code = COALESCE(NULLIF($2::text, ''), u.learning_language)")
	assert.Contains(t, sql, "lp.band_confidence::float8")
	assert.NotContains(t, strings.Join(strings.Fields(LoadStatedOnlySQL), " "), "learner_profiles")
}

func TestLoadResolvesEachUserAndDefaultsMissing(t *testing.T) {
	measured, statedOnly, missing := uuid.New(), uuid.New(), uuid.New()
	fresh := loadNow.Add(-time.Hour)
	q := &fakeQuerier{reply: func(_ string, _ []string) [][]any {
		return [][]any{
			{measured.String(), "B1", "A2", "measured", 0.8, fresh, "steady", fresh},
			{statedOnly.String(), "B2", nil, nil, nil, nil, nil, nil},
			{missing.String(), nil, nil, nil, nil, nil, nil, nil},
		}
	}}
	got, err := Load(context.Background(), q, []uuid.UUID{measured, statedOnly, missing, measured}, "fi", loadNow, DefaultRule())
	require.NoError(t, err)
	require.Len(t, q.calls, 1)
	assert.Len(t, q.calls[0][0], 3, "duplicates collapse")
	assert.Equal(t, "fi", q.calls[0][1])
	assert.Equal(t, Level{"A2", SourceMeasured}, got[measured].Level)
	assert.Equal(t, "steady", got[measured].Stage)
	assert.Equal(t, Level{"B2", SourceStated}, got[statedOnly].Level)
	assert.Equal(t, Level{"A1", SourceDefault}, got[missing].Level)
}

func TestLoadIdAbsentFromRowsGetsDefault(t *testing.T) {
	id := uuid.New()
	q := &fakeQuerier{reply: func(string, []string) [][]any { return nil }}
	got, err := Load(context.Background(), q, []uuid.UUID{id}, "", loadNow, DefaultRule())
	require.NoError(t, err)
	assert.Equal(t, SourceDefault, got[id].Source)
}

func TestLoadChunksOfOneThousand(t *testing.T) {
	ids := make([]uuid.UUID, 2500)
	for i := range ids {
		ids[i] = uuid.New()
	}
	q := &fakeQuerier{reply: func(_ string, ids []string) [][]any {
		rows := make([][]any, len(ids))
		for i, id := range ids {
			rows[i] = []any{id, "A2", nil, nil, nil, nil, nil, nil}
		}
		return rows
	}}
	got, err := Load(context.Background(), q, ids, "", loadNow, DefaultRule())
	require.NoError(t, err)
	require.Len(t, q.calls, 3)
	assert.Len(t, q.calls[0][0], 1000)
	assert.Len(t, q.calls[2][0], 500)
	assert.Len(t, got, 2500)
}

func TestLoadDegradesToStatedWhenProfilesUnreadable(t *testing.T) {
	for _, code := range []string{"42P01", "42501"} {
		id := uuid.New()
		q := &fakeQuerier{
			errs: []error{&pgconn.PgError{Code: code}},
			reply: func(sql string, _ []string) [][]any {
				assert.NotContains(t, sql, "learner_profiles")
				return [][]any{{id.String(), "B1"}}
			},
		}
		got, err := Load(context.Background(), q, []uuid.UUID{id}, "fi", loadNow, DefaultRule())
		require.NoError(t, err, code)
		assert.Equal(t, Level{"B1", SourceStated}, got[id].Level)
		require.Len(t, q.sqls, 2)
	}
}

func TestLoadOtherErrorsFail(t *testing.T) {
	q := &fakeQuerier{errs: []error{errors.New("boom")}, reply: func(string, []string) [][]any { return nil }}
	_, err := Load(context.Background(), q, []uuid.UUID{uuid.New()}, "", loadNow, DefaultRule())
	require.ErrorContains(t, err, "boom")
	_, err = Load(context.Background(), &fakeQuerier{errs: []error{&pgconn.PgError{Code: "57014"}}, reply: nil}, []uuid.UUID{uuid.New()}, "", loadNow, DefaultRule())
	require.Error(t, err)
}

func TestLoadNoIDsNoQuery(t *testing.T) {
	q := &fakeQuerier{}
	got, err := Load(context.Background(), q, nil, "", loadNow, DefaultRule())
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Empty(t, q.calls)
}

func TestUnreadable(t *testing.T) {
	assert.True(t, Unreadable(&pgconn.PgError{Code: "42P01"}))
	assert.True(t, Unreadable(&pgconn.PgError{Code: "42501"}))
	assert.False(t, Unreadable(&pgconn.PgError{Code: "23505"}))
	assert.False(t, Unreadable(errors.New("x")))
	assert.False(t, Unreadable(nil))
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

	now := time.Now().UTC()
	newUser := func(stated any) uuid.UUID {
		id := uuid.New()
		_, err := tx.Exec(ctx, `INSERT INTO users.users (id, email, learning_language, estimated_skill_level) VALUES ($1, $2, 'fi', $3)`,
			id.String(), "level-"+id.String()[:8]+"@example.test", stated)
		require.NoError(t, err)
		return id
	}
	profile := func(id uuid.UUID, lang, cefr, source string, conf float64, age time.Duration) {
		_, err := tx.Exec(ctx, `
			INSERT INTO klearn.learner_profiles
				(user_id, learning_language_code, level_band, cefr_estimate, band_confidence, band_source, stage, stage_since, computed_at)
			VALUES ($1, $2, 'foundation', $3, $4, $5, 'steady', now(), now() - make_interval(secs => $6::float8))`,
			id.String(), lang, cefr, conf, source, age.Seconds())
		require.NoError(t, err)
	}

	measured := newUser("B1")
	profile(measured, "fi", "A2", "measured", 0.8, time.Hour)
	stale := newUser("B1")
	profile(stale, "fi", "A2", "measured", 0.9, 48*time.Hour)
	statedSource := newUser("B2")
	profile(statedSource, "fi", "A2", "stated", 0.9, time.Hour)
	otherLang := newUser("B1")
	profile(otherLang, "sv", "A2", "measured", 0.9, time.Hour)
	noLevel := newUser(nil)
	missing := uuid.New()

	got, err := Load(ctx, tx, []uuid.UUID{measured, stale, statedSource, otherLang, noLevel, missing}, "", now, DefaultRule())
	require.NoError(t, err)
	assert.Equal(t, Level{"A2", SourceMeasured}, got[measured].Level)
	assert.Equal(t, "steady", got[measured].Stage)
	assert.Equal(t, Level{"B1", SourceStated}, got[stale].Level)
	assert.Empty(t, got[stale].Stage)
	assert.Equal(t, Level{"B2", SourceStated}, got[statedSource].Level)
	assert.Equal(t, Level{"B1", SourceStated}, got[otherLang].Level, "another language's profile is not used")
	assert.Equal(t, Level{"A1", SourceDefault}, got[noLevel].Level)
	assert.Equal(t, Level{"A1", SourceDefault}, got[missing].Level)
}
