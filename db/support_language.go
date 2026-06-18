package db

import (
	"context"
	"strings"
)

// supportLanguageCtxKey is the type-safe key for stashing the support
// (UI/translation) language on a request context. Kept separate from
// the learning-language `ctxKey{}` because the two signals carry
// different semantics: learning language scopes the DB search_path,
// support language scopes which localized translations are emitted to
// the client. A user can be learning Finnish (`fi`) while having a
// Vietnamese UI (`vi`); both must live independently on the same ctx.
type supportLanguageCtxKey struct{}

// WithSupportLanguage attaches a support language code to ctx. The
// language string is stored verbatim — validation lives in the caller
// (typically `middleware.ResolveSupportLanguageStateless` runs
// `locale.IsSupportedSupportLanguage` before stashing). Returns the
// original ctx unchanged for empty input so background workers without
// a request scope fall back to "no support language" cleanly.
//
// Sibling to `WithLanguage` for learning language. The two helpers
// live in the same package because their canonical consumers
// (`kielo-shared/observe/httputil.ApplyActiveLanguageQuery` +
// `ApplySupportLanguageQuery`) read from the same package without
// triggering an import cycle.
func WithSupportLanguage(ctx context.Context, code string) context.Context {
	code = strings.TrimSpace(code)
	if code == "" {
		return ctx
	}
	return context.WithValue(ctx, supportLanguageCtxKey{}, code)
}

// SupportLanguageFromContext returns the code attached by
// `WithSupportLanguage`, or "" if none. Sibling to `LanguageFromContext`
// for learning language.
func SupportLanguageFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if code, ok := ctx.Value(supportLanguageCtxKey{}).(string); ok {
		return code
	}
	return ""
}
