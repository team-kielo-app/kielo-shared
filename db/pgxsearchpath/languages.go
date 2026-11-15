package pgxsearchpath

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	sharedDB "github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

// ListActiveLearningLanguageCodes returns the canonical base codes of every active
// authored learning language, ordered. Periodic background workers iterate
// over the result and wrap each tick body in `sharedDB.WithLanguage(ctx, code)`
// so per-language schema writes resolve through `make_per_language_search_path`
// correctly.
//
// localization.languages also contains support/localization locales such as
// Vietnamese. Those are intentionally filtered out here because they do not
// have learning schemas.
//
// The query runs inside a read-only transaction with the resolver's
// fallback search_path applied — `localization.languages` lives in the
// global `localization` schema, not under any per-language prefix, so
// fanout-style callers don't need an active language on ctx to discover
// what languages exist.
//
// Tagged with WithExpectedFallback because hitting the silent-fallback
// path IS the documented contract here: the query is global, has no
// per-language scope to attach. Without this tag the
// kielo_per_language_search_path_fallback_total metric would WARN-once
// on first call from every service that runs a periodic fan-out
// worker (cms cleanup, cms KTV polling, etc.), false-flagging an
// intentional design as a bug.
//
// The list changes only when a language is added, so it is cached per pool for
// ActiveLanguagesCacheTTL: every fan-out tick of every Go service ran this
// read-only transaction (about 4 statements), 413 times an hour on the prod
// primary (2026-11-15). An error or an empty list is never cached.
func ListActiveLearningLanguageCodes(ctx context.Context, db TxBeginner) ([]string, error) {
	if codes, ok := activeLanguagesCache.get(db, time.Now()); ok {
		return codes, nil
	}
	codes, err := listActiveLearningLanguageCodes(ctx, db)
	if err == nil && len(codes) > 0 {
		activeLanguagesCache.put(db, codes, time.Now())
	}
	return codes, err
}

// ActiveLanguagesCacheTTL bounds how long a newly activated language waits
// before fan-out workers include it.
const ActiveLanguagesCacheTTL = 5 * time.Minute

type cachedLanguages struct {
	codes []string
	at    time.Time
}

type languagesCache struct {
	mu      sync.Mutex
	entries map[TxBeginner]cachedLanguages
}

var activeLanguagesCache = &languagesCache{entries: map[TxBeginner]cachedLanguages{}}

func cacheable(db TxBeginner) bool {
	return db != nil && reflect.TypeOf(db).Comparable()
}

func (c *languagesCache) get(db TxBeginner, now time.Time) ([]string, bool) {
	if !cacheable(db) {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[db]
	if !ok || now.Sub(entry.at) >= ActiveLanguagesCacheTTL {
		return nil, false
	}
	return append([]string(nil), entry.codes...), true
}

func (c *languagesCache) put(db TxBeginner, codes []string, now time.Time) {
	if !cacheable(db) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[db] = cachedLanguages{codes: append([]string(nil), codes...), at: now}
}

func listActiveLearningLanguageCodes(ctx context.Context, db TxBeginner) ([]string, error) {
	ctx = sharedDB.WithExpectedFallback(ctx, "pgxsearchpath.list_active_languages")
	const sql = `
		SELECT code
		FROM localization.languages
		WHERE is_active = TRUE
		ORDER BY code
	`
	var codes []string
	err := WithReadTx(ctx, db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var code string
			if err := rows.Scan(&code); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if normalized := locale.NormalizeLearningLanguageCode(code); normalized != "" {
				codes = append(codes, normalized)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("pgxsearchpath: list active learning languages: %w", err)
	}
	return codes, nil
}
