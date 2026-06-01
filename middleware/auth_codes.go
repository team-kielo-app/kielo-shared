package middleware

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	kerrors "github.com/team-kielo-app/kielo-shared/errors"
)

// Sweep ZZZZ + Sweep DDDDD: AUTH_* error codes the auth middleware
// emits. Pre-DDDDD these were declared inline in this file (Sweep
// ZZZZ); Sweep DDDDD relocates the canonical declarations to
// kielo-shared/errors/auth.go so the auth-service handler package
// + mobile + admin-ui can reference the same SoT without copying
// the wire strings.
//
// Pre-DDDDD declaration shape was `const AuthCodeFoo = "AUTH_FOO"`
// (untyped string). Post-DDDDD these are typed aliases via the
// `kerrors.Code*` constants. Back-compat: the alias values stay
// `string` (via Code.String() implicit-convert) so the 9 inline
// references in this package + kielo-auth-service continue to
// type-check unchanged.
const (
	// Token / session lifecycle
	AuthCodeTokenMissing          = string(kerrors.CodeAuthTokenMissing)
	AuthCodeTokenMalformed        = string(kerrors.CodeAuthTokenMalformed)
	AuthCodeTokenExpired          = string(kerrors.CodeAuthTokenExpired)
	AuthCodeTokenSignatureInvalid = string(kerrors.CodeAuthTokenSignatureInvalid)
	AuthCodeTokenIssuerInvalid    = string(kerrors.CodeAuthTokenIssuerInvalid)
	AuthCodeTokenClaimsInvalid    = string(kerrors.CodeAuthTokenClaimsInvalid)
	AuthCodeSessionInvalid        = string(kerrors.CodeAuthSessionInvalid)

	// User-state
	AuthCodeUserDeleted     = string(kerrors.CodeAuthUserDeleted)
	AuthCodeUserCheckFailed = string(kerrors.CodeAuthUserCheckFailed)

	// Authorization (role)
	AuthCodeAdminRequired = string(kerrors.CodeAuthAdminRequired)
	AuthCodeAuthRequired  = string(kerrors.CodeAuthAuthRequired)
)

// AuthCodedError is an alias for kielo-shared/errors.CodedError —
// they are the same struct with identical JSON shape + identical
// CodedHTTPError implementation. Pre-DDDDD this was declared inline
// here (Sweep ZZZZ); Sweep DDDDD dedupes to the central type.
//
// New code should use kerrors.CodedError directly; AuthCodedError is
// kept for back-compat with existing references.
type AuthCodedError = kerrors.CodedError

// authErr is a back-compat shim — new code should use
// kerrors.Coded(status, kerrors.Code*, message) directly. The
// auth-service handler package's authError() helper has the same
// shape and the same migration path.
func authErr(status int, code, message string) *echo.HTTPError {
	return echo.NewHTTPError(status, AuthCodedError{ErrorCode: code, Message: message})
}

// classifyJWTError inspects a jwt.ParseWithClaims error and returns
// the (code, message) tuple that best describes the failure mode.
// Mobile branches on the code:
//
//	AUTH_TOKEN_EXPIRED          → attempt silent refresh
//	AUTH_TOKEN_SIGNATURE_INVALID → force re-login (token was tampered)
//	AUTH_TOKEN_ISSUER_INVALID   → force re-login (wrong env / dev token)
//	AUTH_TOKEN_MALFORMED        → force re-login (corrupt storage)
//	AUTH_TOKEN_CLAIMS_INVALID   → force re-login (server-side bug or schema change)
//
// All paths return 401 — the differentiation is in the code, not the
// status. Pre-ZZZZ all failures collapsed to 401 + "Invalid token".
func classifyJWTError(err error) (code, message string) {
	switch {
	case isJWTErr(err, jwt.ErrTokenExpired):
		return AuthCodeTokenExpired,
			"Your session has expired. Please log in again."
	case isJWTErr(err, jwt.ErrTokenSignatureInvalid):
		return AuthCodeTokenSignatureInvalid,
			"Your session is no longer valid. Please log in again."
	case isJWTErr(err, jwt.ErrTokenInvalidIssuer):
		return AuthCodeTokenIssuerInvalid,
			"Your session is from a different environment. Please log in again."
	case isJWTErr(err, jwt.ErrTokenMalformed):
		return AuthCodeTokenMalformed,
			"Your session token is corrupted. Please log in again."
	case isJWTErr(err, jwt.ErrTokenRequiredClaimMissing):
		return AuthCodeTokenClaimsInvalid,
			"Your session token is missing required information. Please log in again."
	case isJWTErr(err, jwt.ErrTokenNotValidYet):
		return AuthCodeTokenClaimsInvalid,
			"Your session token is not yet valid. Please try again in a moment."
	default:
		// Unknown JWT error shape — return generic AUTH_SESSION_INVALID
		// so the client still gets a typed code, not a default-401.
		return AuthCodeSessionInvalid,
			"Your session is no longer valid. Please log in again."
	}
}

// isJWTErr wraps errors.Is + the jwt sentinel comparison. The jwt
// library returns joined errors via errors.Join (jwt.ValidationError
// composite); errors.Is walks the tree.
func isJWTErr(err error, target error) bool {
	return errors.Is(err, target)
}
