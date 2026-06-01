package errors

import "github.com/labstack/echo/v4"

// CodedError is the unified replacement for three near-identical
// struct definitions that existed pre-DDDDD:
//
//   - kielo-shared/middleware/auth_codes.go     AuthCodedError
//   - kielo-auth-service/internal/handlers/    AuthErrorBody
//   - kielo-mobile-bff/internal/utils/         bffCodedError
//
// All three had the same JSON shape (`{"error_code", "message"}`)
// and the same interface signatures
// (HTTPErrorCode() / HTTPErrorMessage()). Sweep DDDDD consolidates.
//
// The struct implements the CodedHTTPError interface used by
// kielo-shared/middleware.CanonicalEchoErrorHandler so the canonical
// envelope handler unpacks the typed code into the response body's
// `error.code` slot.
//
// Wire shape on a 401 with code=AUTH_TOKEN_EXPIRED:
//
//	{"error": {"code": "AUTH_TOKEN_EXPIRED",
//	           "message": "Your session has expired. Please log in again.",
//	           "trace_id": "..."},
//	 "message": "Your session has expired. Please log in again."}
type CodedError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

// HTTPErrorCode satisfies the CodedHTTPError interface in
// kielo-shared/middleware (declared at errors.go:127-130).
func (e CodedError) HTTPErrorCode() string { return e.ErrorCode }

// HTTPErrorMessage satisfies the CodedHTTPError interface.
func (e CodedError) HTTPErrorMessage() string { return e.Message }

// Coded wraps (status, code, message) into an *echo.HTTPError carrying
// the CodedError body — the CanonicalEchoErrorHandler unpacks it via
// the CodedHTTPError interface. This replaces the three near-identical
// helpers `authErr` (middleware), `authError` (auth-service handler),
// `bffError` (mobile-bff utils) — all three reduce to a single call:
//
//	return errors.Coded(http.StatusUnauthorized,
//	    errors.CodeAuthTokenExpired,
//	    "Your session has expired. Please log in again.")
func Coded(status int, code Code, message string) *echo.HTTPError {
	return echo.NewHTTPError(status, CodedError{
		ErrorCode: string(code),
		Message:   message,
	})
}

// NewCodedError constructs a CodedError value (without the echo wrap).
// Useful for tests + for callers that need the struct without going
// through Echo's HTTPError machinery.
func NewCodedError(code Code, message string) CodedError {
	return CodedError{ErrorCode: string(code), Message: message}
}
