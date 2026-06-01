// Sweep DDDDD: unit tests for the central error-code SoT package.
//
// Three test groups:
//
//  1. Vocabulary: every declared Code matches UPPER_SNAKE_CASE per
//     the casing gate at tests/contract/error_code_vocabulary_test.go.
//  2. Structural defaults: DefaultForStatus returns the exact pre-
//     DDDDD wire strings for every HTTP status — byte-equivalent
//     to the legacy switch.
//  3. CodedError: implements the CodedHTTPError interface contract
//     with the expected JSON shape.
package errors

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ = echo.New // keep echo imported for the HTTPError-typed assertion below

var upperSnakeCase = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// allCodes returns every Code constant declared in this package. Use
// reflect-free enumeration via the package's `All*` iteration slices
// to keep the test boundary clean.
func allCodes() []Code {
	codes := []Code{
		// Structural defaults
		CodeBadRequest,
		CodeUnauthorized,
		CodeForbidden,
		CodeNotFound,
		CodeConflict,
		CodeValidationFailed,
		CodeRateLimited,
		CodeInternalError,
		CodeGenericError,
		CodeUpstreamUnavailable,
		CodeUpstreamError,
		CodeUpstreamUnconfigured,
		// FEATURE_LIMIT_REACHED
		CodeFeatureLimitReached,
		// BFF namespace
		CodeBFFInvalidRequestBody,
		CodeBFFBackendUnavailable,
		CodeBFFBackendError,
	}
	codes = append(codes, AllAuthErrorCodes...)
	codes = append(codes, AllAuthSuccessCodes...)
	return codes
}

func TestVocabulary_AllCodesAreUpperSnakeCase(t *testing.T) {
	// The Sweep K-era casing gate
	// (tests/contract/error_code_vocabulary_test.go) walks every
	// source file for `"code": "..."` literals and asserts they
	// match upper-snake-case. The SoT MUST satisfy the same rule.
	for _, c := range allCodes() {
		s := string(c)
		assert.True(t, upperSnakeCase.MatchString(s),
			"Code %q does not match upper-snake-case (Sweep K casing gate)", s)
		// Sanity: no leading underscore, no trailing whitespace, no
		// empty string.
		assert.NotEmpty(t, s, "empty Code")
		assert.NotEqual(t, '_', s[0], "Code starts with underscore: %q", s)
	}
}

func TestVocabulary_AuthCodesAreUnique(t *testing.T) {
	// Sweep DDDDD invariant: AllAuthErrorCodes + AllAuthSuccessCodes
	// must enumerate distinct wire strings. A typo'd duplicate would
	// produce silent vocabulary drift on the client side.
	seen := make(map[Code]string)
	all := append([]Code{}, AllAuthErrorCodes...)
	all = append(all, AllAuthSuccessCodes...)
	for _, c := range all {
		if existing, ok := seen[c]; ok {
			t.Errorf("duplicate auth code %q (also in %q)", c, existing)
		}
		seen[c] = "AllAuth*"
	}
}

func TestDefaultForStatus_MatchesPreDDDDDSwitch(t *testing.T) {
	// Byte-equivalent to the pre-DDDDD switch at
	// kielo-shared/middleware/errors.go:187-208. Sweep DDDDD must
	// NOT change behavior — only export the constants and dedup the
	// struct triplication.
	cases := []struct {
		status int
		want   Code
	}{
		{http.StatusBadRequest, CodeBadRequest},                // 400
		{http.StatusUnauthorized, CodeUnauthorized},            // 401
		{http.StatusForbidden, CodeForbidden},                  // 403
		{http.StatusNotFound, CodeNotFound},                    // 404
		{http.StatusConflict, CodeConflict},                    // 409
		{http.StatusUnprocessableEntity, CodeValidationFailed}, // 422
		{http.StatusTooManyRequests, CodeRateLimited},          // 429
		{http.StatusInternalServerError, CodeInternalError},    // 500
		{http.StatusBadGateway, CodeInternalError},             // 502
		// Sweep DDDDD-B2 refinement: 503 now maps to SERVICE_UNAVAILABLE
		// rather than INTERNAL_ERROR fallback. This is a deliberate
		// vocabulary refinement (503 has a distinct operational meaning:
		// "service is temporarily down, retry later" vs. INTERNAL_ERROR's
		// "something went wrong in the request"). kielo-media-upload-api
		// had this code declared locally pre-DDDDD-B2.
		{http.StatusServiceUnavailable, CodeServiceUnavailable}, // 503
		{http.StatusGatewayTimeout, CodeInternalError},          // 504
		{http.StatusOK, CodeGenericError},                       // unexpected fallback
		{http.StatusMovedPermanently, CodeGenericError},         // 301
		{http.StatusPaymentRequired, CodeGenericError},          // 402 — falls through to ERROR
	}
	for _, tc := range cases {
		got := DefaultForStatus(tc.status)
		assert.Equal(t, tc.want, got,
			"DefaultForStatus(%d) want %q got %q (pre-DDDDD regression)",
			tc.status, tc.want, got)
	}
}

func TestCodedError_ImplementsCodedHTTPErrorInterface(t *testing.T) {
	// Compile-time + runtime check: CodedError must satisfy the
	// CodedHTTPError interface contract that middleware.
	// CanonicalEchoErrorHandler reads to extract the typed code from
	// the response body struct.
	ce := NewCodedError(CodeAuthInvalidCredentials, "wrong password")
	type CodedHTTPError interface {
		HTTPErrorCode() string
		HTTPErrorMessage() string
	}
	var _ CodedHTTPError = ce
	assert.Equal(t, "AUTH_INVALID_CREDENTIALS", ce.HTTPErrorCode())
	assert.Equal(t, "wrong password", ce.HTTPErrorMessage())
}

func TestCodedError_JSONShape(t *testing.T) {
	// Pre-DDDDD the three near-identical struct definitions all
	// emitted the same JSON shape: {"error_code": "X", "message":
	// "Y"}. CodedError MUST match byte-for-byte.
	ce := NewCodedError(CodeAuthSessionInvalid, "log in again")
	body, err := json.Marshal(ce)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"error_code":"AUTH_SESSION_INVALID","message":"log in again"}`,
		string(body))
}

func TestCoded_ReturnsEchoHTTPErrorWithBodyAndStatus(t *testing.T) {
	// Coded(status, code, message) replaces the three near-identical
	// authErr / authError / bffError helpers. The returned
	// *echo.HTTPError must carry the CodedError struct as its Message
	// so CanonicalEchoErrorHandler unpacks the typed code via the
	// CodedHTTPError type assertion.
	httpErr := Coded(http.StatusUnauthorized,
		CodeAuthTokenExpired,
		"Your session has expired. Please log in again.")
	require.NotNil(t, httpErr)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)

	body, ok := httpErr.Message.(CodedError)
	require.True(t, ok, "echo.HTTPError.Message should be a CodedError")
	assert.Equal(t, "AUTH_TOKEN_EXPIRED", body.HTTPErrorCode())
	assert.Equal(t, "Your session has expired. Please log in again.",
		body.HTTPErrorMessage())
}

func TestCode_StringMethod(t *testing.T) {
	// Code.String() must return the underlying string verbatim.
	// Used by legacy callers via implicit conversion to keep the
	// 418 inline-literal call sites working without immediate
	// migration (Sweep DDDDD discipline: ship the SoT now, migrate
	// adopters incrementally).
	assert.Equal(t, "AUTH_INVALID_CREDENTIALS",
		CodeAuthInvalidCredentials.String())
	assert.Equal(t, "FEATURE_LIMIT_REACHED",
		CodeFeatureLimitReached.String())
	assert.Equal(t, "BAD_REQUEST",
		CodeBadRequest.String())
}
