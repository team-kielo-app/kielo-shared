package pgxsearchpath

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// SetSearchPathOnConnect returns a pgxpool.Config-compatible AfterConnect
// handler that issues `SET search_path TO <path>` on every new pool
// connection. The path is validated against the same schema-identifier
// rules used by the per-language SET LOCAL machinery — only plain
// identifiers (matching [A-Za-z_][A-Za-z0-9_]*) are accepted, so callers
// can't accidentally inject SQL via the path string.
//
// This consolidates the same closure each Kielo service used to write
// inside its db package's InitDB:
//
//	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
//	    _, err := conn.Exec(ctx, "SET search_path TO <service-specific path>")
//	    return err
//	}
//
// Validation panics at construction time (path is a programmer-supplied
// constant; an invalid path is a programmer error, not a runtime
// fallible) so the pool can't start with a bad config.
func SetSearchPathOnConnect(path string) func(context.Context, *pgx.Conn) error {
	cleaned, err := sharedDB.SanitizeSearchPath(path)
	if err != nil {
		panic(fmt.Sprintf("pgxsearchpath: invalid search_path %q: %v", path, err))
	}
	stmt := "SET search_path TO " + cleaned
	return func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, stmt)
		return err
	}
}
