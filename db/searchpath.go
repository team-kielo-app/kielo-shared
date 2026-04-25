// Package db provides shared database helpers for kielo services.
//
// The search_path machinery here mirrors kielo_shared.db_utils on the
// Python side: per-request search_path resolution for schema-per-language
// routing, robust under PgBouncer transaction pooling.
//
// Wiring (Echo handlers):
//
//  1. Auth/JWT middleware extracts the active learning language from the
//     request (claim, header, or path param) and calls db.WithLanguage(ctx, lang)
//     to attach it to the request context.
//  2. Repository BeginTx wrappers call db.IssueSearchPathForContext at the
//     top of every transaction, before any other statement, to issue
//     SET LOCAL search_path with the per-language schemas.
//
// Static-path callers (services that own a fixed schema set, e.g. ingest
// workers operating only on _shared) call db.IssueStaticSearchPath instead.
//
// SQL-injection guard: only validated language identifiers and
// pre-validated schema templates reach the SET statement. Untrusted input
// is rejected by ValidateLanguageIdent before formatting.
package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var _ = errors.Is // ensure errors is used for ApplySearchPathToTx

// DefaultPerLanguageSearchPathTemplate is the canonical schema layout
// during the M3 transition window. Per-language schemas (klearn_<lang>,
// cms_<lang>) come first; legacy klearn / cms stay on the path until
// M6 cutover so reads of not-yet-partitioned tables still resolve.
// users / localization / communications / convo / media stay where they
// are — already cross-language by construction. public is last for
// pgvector and other extensions.
const DefaultPerLanguageSearchPathTemplate = "klearn_{lang}, cms_{lang}, klearn, cms, " +
	"users, localization, communications, convo, media, public"

// ErrNoActiveLanguage is returned by IssueSearchPathForContext when the
// caller didn't attach a language to ctx via WithLanguage. The repository
// layer should treat this as a programmer error: per-request handlers
// must run after a language-extracting middleware.
var ErrNoActiveLanguage = errors.New("kielo-shared/db: no active language on context")

// languageIdentRe matches ISO 639-1/639-3 lowercase codes with an
// optional uppercase region (e.g. "fi", "sv", "vi", "zh_CN"). Stricter
// than the search_path identifier regex on purpose: language codes
// only, since the result is interpolated into a schema name.
var languageIdentRe = regexp.MustCompile(`^[a-z]{2,3}(_[A-Z]{2})?$`)

// searchPathIdentRe matches a single schema identifier. Used to validate
// the result of formatting a template before issuing SET search_path,
// because that statement can't be parameterized.
var searchPathIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type ctxKey struct{}

// WithLanguage attaches a validated language code to ctx. Returns the
// original ctx unchanged if lang fails ValidateLanguageIdent, so callers
// that pass through user input fall back safely to "no language" rather
// than poisoning the context. Use ValidateLanguageIdent directly if you
// want bad input to fail loud.
func WithLanguage(ctx context.Context, lang string) context.Context {
	if err := ValidateLanguageIdent(lang); err != nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, lang)
}

// LanguageFromContext returns the language attached by WithLanguage, or
// "" and false if none.
func LanguageFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	lang, ok := ctx.Value(ctxKey{}).(string)
	if !ok || lang == "" {
		return "", false
	}
	return lang, true
}

// ValidateLanguageIdent rejects anything that isn't a recognizable
// language code. The result is interpolated into a schema name; looser
// identifier rules would let arbitrary identifiers through.
func ValidateLanguageIdent(lang string) error {
	if !languageIdentRe.MatchString(lang) {
		return fmt.Errorf(
			"kielo-shared/db: invalid language identifier %q (expected ISO 639 lowercase with optional region, e.g. \"fi\", \"sv\", \"zh_CN\")",
			lang,
		)
	}
	return nil
}

// validateSearchPathIdents rejects any element that isn't a plain
// identifier. Mirrors _validate_search_path_idents in db_utils.py.
func validateSearchPathIdents(searchPath string) (string, error) {
	parts := strings.Split(searchPath, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !searchPathIdentRe.MatchString(part) {
			return "", fmt.Errorf(
				"kielo-shared/db: invalid search_path identifier %q (only [A-Za-z_][A-Za-z0-9_]* allowed)",
				part,
			)
		}
		cleaned = append(cleaned, part)
	}
	return strings.Join(cleaned, ","), nil
}

// BuildSearchPath formats a per-language template by substituting {lang}.
// Validates lang first, then validates the formatted result. Returns the
// canonicalised (whitespace-trimmed, comma-joined) string suitable for
// SET search_path TO ....
func BuildSearchPath(lang, template string) (string, error) {
	if err := ValidateLanguageIdent(lang); err != nil {
		return "", err
	}
	formatted := strings.ReplaceAll(template, "{lang}", lang)
	return validateSearchPathIdents(formatted)
}

// IssueRaw issues SET LOCAL search_path TO <path> on exec. The exec
// closure is the caller's transaction handle; this avoids tying us to
// any particular driver's *Tx type. Call once at the top of every
// transaction, before any other statement.
//
// SET LOCAL applies for the duration of the current transaction only,
// so it survives PgBouncer reusing backends across transactions.
func IssueRaw(ctx context.Context, path string, exec func(ctx context.Context, query string) error) error {
	cleaned, err := validateSearchPathIdents(path)
	if err != nil {
		return err
	}
	return exec(ctx, "SET LOCAL search_path TO "+cleaned)
}

// IssueStaticSearchPath issues SET LOCAL search_path with a fixed path.
// Use for services that own a single schema set (e.g. ingest workers
// operating only on _shared content).
func IssueStaticSearchPath(ctx context.Context, path string, exec func(ctx context.Context, query string) error) error {
	return IssueRaw(ctx, path, exec)
}

// IssueSearchPathForContext reads the active language from ctx (set by
// WithLanguage) and issues SET LOCAL search_path with the per-language
// schemas. Returns ErrNoActiveLanguage if no language is on ctx.
//
// template should typically be DefaultPerLanguageSearchPathTemplate. Pass
// a custom template if a service needs a non-standard layout (e.g. read
// replicas with a different schema order).
func IssueSearchPathForContext(
	ctx context.Context,
	template string,
	exec func(ctx context.Context, query string) error,
) error {
	lang, ok := LanguageFromContext(ctx)
	if !ok {
		return ErrNoActiveLanguage
	}
	path, err := BuildSearchPath(lang, template)
	if err != nil {
		return err
	}
	return exec(ctx, "SET LOCAL search_path TO "+path)
}

// ApplySearchPathToTx is the standard repository-side helper for
// per-request search_path routing. Call it once at the top of every
// read transaction that should be language-scoped. The exec closure
// adapts whichever pgx-or-database/sql tx type the service uses.
//
// Behavior:
//   - If ctx has no active language attached (legacy callers, background
//     workers without per-request context), returns nil — the connection-
//     level search_path applies.
//   - If ctx has an active language, issues SET LOCAL search_path with
//     the standard per-language template.
//   - Returns nil for ErrNoActiveLanguage; surfaces other errors
//     (validation failure, exec failure) wrapped with context.
//
// This consolidates the helper that was previously duplicated in
// kielo-cms/internal/repository/content_repository.go so every service
// uses the same recipe.
func ApplySearchPathToTx(
	ctx context.Context,
	exec func(ctx context.Context, query string) error,
) error {
	if _, ok := LanguageFromContext(ctx); !ok {
		return nil
	}
	if err := IssueSearchPathForContext(
		ctx, DefaultPerLanguageSearchPathTemplate, exec,
	); err != nil {
		if errors.Is(err, ErrNoActiveLanguage) {
			return nil
		}
		return fmt.Errorf("kielo-shared/db: ApplySearchPathToTx: %w", err)
	}
	return nil
}

// TxBeginner is the minimal pgx-or-database/sql contract: anything that
// can start a transaction with a context. Both pgxpool.Pool and
// *pgx.Conn satisfy this; database/sql users wrap in a small adapter.
//
// We deliberately use `any` for the result so the helper works with
// pgx.Tx (which is an interface, not *sql.Tx). Callers cast the result
// to their driver's tx type.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts any) (any, error)
}

// PgxTx is the interface every pgx transaction satisfies — declared
// here to avoid importing pgx into kielo-shared/db (kielo-shared/db
// stays driver-agnostic).
type PgxTx interface {
	Exec(ctx context.Context, sql string, args ...any) (any, error)
	Rollback(ctx context.Context) error
	Commit(ctx context.Context) error
}

// BeginTxWithSearchPath opens a transaction via `begin` and issues
// SET LOCAL search_path inside it before any other statement. If ctx
// carries an active language, the per-language template is used;
// otherwise the connection-level search_path applies (no SET issued).
//
// Usage in a kielo-cms repository:
//
//	tx, err := db.BeginTxWithSearchPath(ctx, func(c context.Context) (db.PgxTx, error) {
//	    return r.db.BeginTx(c, pgx.TxOptions{})
//	}, db.DefaultPerLanguageSearchPathTemplate)
//	if err != nil { return err }
//	defer tx.Rollback(ctx)
//	// ... run queries on tx ...
//	return tx.Commit(ctx)
//
// The closure indirection keeps kielo-shared/db driver-agnostic: pgx
// callers write a one-line pgx.BeginTx; database/sql callers write
// theirs. The helper itself only knows how to issue SET LOCAL on
// whatever PgxTx-shaped value the closure returns.
func BeginTxWithSearchPath(
	ctx context.Context,
	begin func(ctx context.Context) (PgxTx, error),
	template string,
) (PgxTx, error) {
	tx, err := begin(ctx)
	if err != nil {
		return nil, err
	}

	// If no active language on ctx, fall back to the connection-level
	// search_path (no SET issued). Repository methods that NEED per-
	// language scoping should treat ErrNoActiveLanguage as a programmer
	// error in their caller — the middleware should always have set it.
	if _, ok := LanguageFromContext(ctx); !ok {
		return tx, nil
	}

	exec := func(c context.Context, query string) error {
		_, err := tx.Exec(c, query)
		return err
	}
	if err := IssueSearchPathForContext(ctx, template, exec); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("kielo-shared/db: BeginTxWithSearchPath: %w", err)
	}
	return tx, nil
}
