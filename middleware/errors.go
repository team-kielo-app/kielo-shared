package middleware

import (
	"log"

	"github.com/labstack/echo/v4"
)

// LogInternalError logs the underlying err with operator-facing context
// and returns an opaque 500 to the client. Use this instead of
// `echo.NewHTTPError(http.StatusInternalServerError, err.Error())`
// which leaks internal error strings (DB constraint names, file paths,
// SQL syntax, internal URLs) to API consumers.
//
// The format string + args produce the operator log line; the client
// receives a generic "internal server error" body. Sites that want to
// expose a more specific user-facing reason should use a 4xx status
// (e.g. echo.NewHTTPError(http.StatusBadRequest, "explicit reason"))
// rather than mixing operator detail into a 5xx response.
//
// Returns *echo.HTTPError so callers can `return middleware.LogInternalError(...)`
// directly from handler functions.
func LogInternalError(c echo.Context, err error, format string, args ...any) *echo.HTTPError {
	// Always log; even if format/args don't capture the err, operators
	// need the underlying detail. Format and args first so call sites
	// can include path/user/id context (which is more useful than the
	// raw error alone).
	log.Printf(format, args...)
	if err != nil {
		log.Printf("  underlying error: %v", err)
	}
	return echo.NewHTTPError(500, "internal server error")
}
