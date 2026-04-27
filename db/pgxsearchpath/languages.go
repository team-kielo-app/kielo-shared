package pgxsearchpath

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ListActiveLanguageCodes returns the canonical base codes ("fi", "sv",
// ...) of every active row in `localization.languages`, ordered. Periodic
// background workers iterate over the result and wrap each tick body in
// `sharedDB.WithLanguage(ctx, code)` so per-language schema writes
// resolve through `make_per_language_search_path` correctly.
//
// Codes are guaranteed valid schema identifiers because of V110's CHECK
// constraint (`code ~ '^[a-z]{2,3}$'`) on `localization.languages.code`,
// so callers can pass the result straight into `WithLanguage` without
// further validation.
//
// The query runs inside a read-only transaction with the resolver's
// fallback search_path applied — `localization.languages` lives in the
// global `localization` schema, not under any per-language prefix, so
// fanout-style callers don't need an active language on ctx to discover
// what languages exist.
func ListActiveLanguageCodes(ctx context.Context, db TxBeginner) ([]string, error) {
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
			codes = append(codes, code)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("pgxsearchpath: list active languages: %w", err)
	}
	return codes, nil
}
