package learnerlevel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the pgx surface Load needs; *pgxpool.Pool, *pgx.Conn and pgx.Tx
// satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadChunk is how many users one query covers.
const LoadChunk = 1000

// statedLevelSQL is the stated level of the language bound as $2 ("" means the
// user's active language): that language's row in users.learner_language_levels,
// or the users.users mirror when it is the active language and has no row.
const statedLevelSQL = `COALESCE(
	(SELECT ll.level FROM users.learner_language_levels ll
	 WHERE ll.user_id = u.id AND ll.learning_language_code = COALESCE(NULLIF($2::text, ''), u.learning_language)),
	CASE WHEN NULLIF(u.learning_language, '') IS NULL
	       OR COALESCE(NULLIF($2::text, ''), u.learning_language) = u.learning_language
	     THEN u.estimated_skill_level END)`

// LoadSQL returns one row per requested id (a user absent from users.users
// still yields one row of NULLs). Ids travel as a text array so the statement
// also runs under pgx's simple protocol.
const LoadSQL = `
SELECT ids.id::text,
  ` + statedLevelSQL + `,
  lp.cefr_estimate, lp.band_source, lp.band_confidence::float8, lp.computed_at, lp.stage, lp.stage_since,
  COALESCE(u.onboarding_completed_at, u.created_at)
FROM unnest($1::text[]) AS ids(id)
LEFT JOIN users.users u ON u.id = ids.id::uuid
LEFT JOIN klearn.learner_profiles lp
  ON lp.user_id = u.id
 AND lp.learning_language_code = COALESCE(NULLIF($2::text, ''), u.learning_language)`

// LoadStatedOnlySQL is LoadSQL without learner_profiles, used when that table
// cannot be read.
const LoadStatedOnlySQL = `
SELECT ids.id::text,
  ` + statedLevelSQL + `,
  COALESCE(u.onboarding_completed_at, u.created_at)
FROM unnest($1::text[]) AS ids(id)
LEFT JOIN users.users u ON u.id = ids.id::uuid`

// Unreadable reports an undefined_table or insufficient_privilege error, the
// two ways klearn.learner_profiles can be unreadable.
func Unreadable(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "42P01" || pgErr.Code == "42501"
}

// Load returns the effective level for every id in one query per LoadChunk
// users. learningLanguage selects the language ("" = each user's active one).
// Users absent from users.users get the default level. A learner_profiles table
// that cannot be read degrades to the stated level.
func Load(
	ctx context.Context,
	q Querier,
	userIDs []uuid.UUID,
	learningLanguage string,
	now time.Time,
	rule Rule,
) (map[uuid.UUID]Result, error) {
	out := make(map[uuid.UUID]Result, len(userIDs))
	seen := make(map[uuid.UUID]struct{}, len(userIDs))
	unique := make([]uuid.UUID, 0, len(userIDs))
	for _, id := range userIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	withMeasured := true
	for start := 0; start < len(unique); start += LoadChunk {
		end := min(start+LoadChunk, len(unique))
		err := loadChunk(ctx, q, unique[start:end], learningLanguage, now, rule, withMeasured, out)
		if withMeasured && Unreadable(err) {
			log.Printf("WARN: learnerlevel: klearn.learner_profiles unreadable, using the stated level: %v", err)
			withMeasured = false
			err = loadChunk(ctx, q, unique[start:end], learningLanguage, now, rule, false, out)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func loadChunk(
	ctx context.Context,
	q Querier,
	ids []uuid.UUID,
	lang string,
	now time.Time,
	rule Rule,
	withMeasured bool,
	out map[uuid.UUID]Result,
) error {
	idText := make([]string, len(ids))
	for i, id := range ids {
		idText[i] = id.String()
	}
	sql := LoadSQL
	if !withMeasured {
		sql = LoadStatedOnlySQL
	}
	rows, err := q.Query(ctx, sql, idText, lang)
	if err != nil {
		return fmt.Errorf("learnerlevel: query: %w", err)
	}
	defer rows.Close()

	got := make(map[uuid.UUID]Result, len(ids))
	for rows.Next() {
		var (
			idStr  string
			stated *string
			m      Measured
		)
		dest := []any{&idStr, &stated}
		if withMeasured {
			dest = append(dest, &m.CEFR, &m.Source, &m.Confidence, &m.ComputedAt, &m.Stage, &m.StageSince)
		}
		dest = append(dest, &m.JoinedAt)
		if err := rows.Scan(dest...); err != nil {
			return fmt.Errorf("learnerlevel: scan: %w", err)
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return fmt.Errorf("learnerlevel: bad id %q: %w", idStr, err)
		}
		s := ""
		if stated != nil {
			s = *stated
		}
		got[id] = Resolve(m, s, now, rule)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("learnerlevel: rows: %w", err)
	}
	for _, id := range ids {
		if r, ok := got[id]; ok {
			out[id] = r
		} else {
			out[id] = Resolve(Measured{}, "", now, rule)
		}
	}
	return nil
}
