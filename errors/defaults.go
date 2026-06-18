package errors

import "net/http"

// Code is the typed string alias for canonical wire-string error
// codes. Using a typed string makes vocabulary drift compile-fail
// rather than a runtime curiosity:
//
//	// Compile error:
//	errors.Coded(500, "Internal-Error", "")    // not a Code constant
//	// OK:
//	errors.Coded(500, errors.CodeInternalError, "")
//
// All Codes in this package satisfy `^[A-Z][A-Z0-9_]*$`
// (UPPER_SNAKE_CASE) per the casing gate at
// tests/contract/error_code_vocabulary_test.go.
type Code string

// String lets a Code be used directly as a string in legacy
// signatures (e.g. middleware.APIError(c, status, code string, ...)).
// Once Sweep DDDDD's adoption phase migrates the 418 inline-literal
// call sites this will no longer be necessary; until then it's the
// boundary that lets central typed constants substitute for raw
// wire strings.
func (c Code) String() string { return string(c) }

// Structural defaults — the 9 codes that the canonical envelope's
// `defaultCodeForStatus(status int)` emits when no explicit code
// is provided. Pre-DDDDD these lived as bare-string literals inside
// the switch at kielo-shared/middleware/errors.go:187-208 and were
// independently re-declared in kielo-media-upload-api/handlers/
// errors.go:14-23.
//
// Emit shape on the wire:
//
//	{"error": {"code": "BAD_REQUEST", "message": "..."}, "message": "..."}
const (
	CodeBadRequest         Code = "BAD_REQUEST"         // 400
	CodeUnauthorized       Code = "UNAUTHORIZED"        // 401
	CodeForbidden          Code = "FORBIDDEN"           // 403
	CodeNotFound           Code = "NOT_FOUND"           // 404
	CodeConflict           Code = "CONFLICT"            // 409
	CodeValidationFailed   Code = "VALIDATION_FAILED"   // 422
	CodeRateLimited        Code = "RATE_LIMITED"        // 429
	CodeInternalError      Code = "INTERNAL_ERROR"      // 5xx
	CodeServiceUnavailable Code = "SERVICE_UNAVAILABLE" // 503
	CodeGenericError       Code = "ERROR"               // fallback when status is unrecognized

	// Sweep DDDDD Tier 1B-promoted-to-1A: upstream-proxy semantics.
	// Emitted by 11+ kielo-cms proxy sites + 6 kielo-user-service
	// klearn-proxy sites + 1 kielo-mobile-bff handler. Currently
	// inline string literals everywhere.
	CodeUpstreamUnavailable  Code = "UPSTREAM_UNAVAILABLE"
	CodeUpstreamError        Code = "UPSTREAM_ERROR"
	CodeUpstreamUnconfigured Code = "UPSTREAM_UNCONFIGURED"
)

// DefaultForStatus returns the canonical Code for a given HTTP
// status. Mirrors the pre-DDDDD switch in kielo-shared/middleware/
// errors.go:187-208 but returns the typed Code instead of a bare
// string. Used by middleware.CanonicalEchoErrorHandler when the
// underlying echo.HTTPError doesn't satisfy CodedHTTPError.
//
// Behavior is byte-equivalent to the pre-DDDDD function — same
// 9-entry mapping, same fallback semantics. Existing callers can
// migrate at their own pace; nothing breaks.
func DefaultForStatus(status int) Code {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusUnprocessableEntity:
		return CodeValidationFailed
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusServiceUnavailable:
		return CodeServiceUnavailable
	}
	if status >= 500 {
		return CodeInternalError
	}
	return CodeGenericError
}
