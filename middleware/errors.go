package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/observe"
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

// ErrorEnvelope is the canonical API error response shape emitted by
// APIError / APIErrorStdlib. The nested Error object is the forward-going
// shape; the top-level Message field is preserved for back-compat with
// older mobile clients that read response.message — deprecate after the
// mobile migration completes.
type ErrorEnvelope struct {
	Error   ErrorBody `json:"error"`
	Message string    `json:"message,omitempty"`
}

// ErrorBody carries the structured fields of an API error. Code is a
// stable machine-readable identifier (e.g. SESSION_NOT_FOUND); Message
// is human-readable; Details is optional structured context;
// TraceID echoes the W3C traceparent ID for log correlation.
type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	TraceID string         `json:"trace_id,omitempty"`
}

// APIError emits the canonical error envelope on an Echo context. If code
// is empty, a sensible default is derived from the HTTP status. The trace
// ID is taken from the request context if present.
//
// Default code mapping:
//
//	400 -> BAD_REQUEST     401 -> UNAUTHORIZED       403 -> FORBIDDEN
//	404 -> NOT_FOUND       409 -> CONFLICT           422 -> VALIDATION_FAILED
//	429 -> RATE_LIMITED    5xx -> INTERNAL_ERROR
func APIError(c echo.Context, status int, code, message string, details map[string]any) error {
	if code == "" {
		code = defaultCodeForStatus(status)
	}
	traceID := traceIDFromContext(c.Request().Context())
	body := ErrorEnvelope{
		Error: ErrorBody{
			Code:    code,
			Message: message,
			Details: details,
			TraceID: traceID,
		},
		Message: message,
	}
	return c.JSON(status, body)
}

// APIErrorStdlib is the http.ResponseWriter equivalent of APIError for
// non-Echo handlers (chi, raw net/http). Behavior and envelope shape
// match APIError exactly.
func APIErrorStdlib(w http.ResponseWriter, ctx context.Context, status int, code, message string, details map[string]any) {
	if code == "" {
		code = defaultCodeForStatus(status)
	}
	traceID := traceIDFromContext(ctx)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{
		Error: ErrorBody{
			Code:    code,
			Message: message,
			Details: details,
			TraceID: traceID,
		},
		Message: message,
	})
}

// CanonicalEchoErrorHandler wraps Echo's default error handler so that
// `echo.NewHTTPError(status, "msg")` and unhandled errors are emitted in
// the canonical ErrorEnvelope shape. Register it in main.go via:
//
//	e.HTTPErrorHandler = middleware.CanonicalEchoErrorHandler
func CanonicalEchoErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	status := http.StatusInternalServerError
	message := "internal server error"
	var details map[string]any
	var code string

	var he *echo.HTTPError
	if errors.As(err, &he) {
		status = he.Code
		switch m := he.Message.(type) {
		case string:
			message = m
		case error:
			message = m.Error()
		default:
			if m != nil {
				if b, mErr := json.Marshal(m); mErr == nil {
					message = string(b)
				}
			}
		}
	} else if err != nil {
		message = err.Error()
	}

	if code == "" {
		code = defaultCodeForStatus(status)
	}

	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(status)
		return
	}
	_ = APIError(c, status, code, message, details)
}

func defaultCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusUnprocessableEntity:
		return "VALIDATION_FAILED"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	}
	if status >= 500 {
		return "INTERNAL_ERROR"
	}
	return "ERROR"
}

func traceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if tc, ok := observe.FromContext(ctx); ok {
		return tc.TraceID
	}
	return ""
}
