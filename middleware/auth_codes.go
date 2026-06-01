package middleware

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Sweep ZZZZ: stable error codes the auth middleware emits so mobile
// + admin clients can localize. Pre-ZZZZ every failure mode collapsed
// to the default UNAUTHORIZED code (with English `message` text like
// "Invalid token" / "Missing authorization header"), which clients
// could not branch on for UX (silent refresh vs force re-login vs
// "your account has been removed").
//
// Mirrors the kielo-auth-service AUTH_* code namespace. Codes live in
// kielo-shared/middleware because the middleware is the only producer;
// auth-service uses its own ErrCode* constants (same vocabulary).
//
// Cross-language note: the canonical SoT for these codes is mirrored
// in `kielo-app/src/features/auth/authErrors.ts` for mobile and
// `kielo-admin-ui/src/store/authErrors.ts` for admin. Sweep ZZZZ ships
// all three in lockstep.
const (
	// Token / session lifecycle
	AuthCodeTokenMissing          = "AUTH_TOKEN_MISSING"           // Authorization header absent
	AuthCodeTokenMalformed        = "AUTH_TOKEN_MALFORMED"         // Bad Bearer prefix or non-JWT body
	AuthCodeTokenExpired          = "AUTH_TOKEN_EXPIRED"           // exp claim has passed
	AuthCodeTokenSignatureInvalid = "AUTH_TOKEN_SIGNATURE_INVALID" // signature does not verify against pubkey
	AuthCodeTokenIssuerInvalid    = "AUTH_TOKEN_ISSUER_INVALID"    // iss claim mismatch
	AuthCodeTokenClaimsInvalid    = "AUTH_TOKEN_CLAIMS_INVALID"    // valid signature, missing required claim
	AuthCodeSessionInvalid        = "AUTH_SESSION_INVALID"         // claims-cast or context-missing on authenticated handler

	// User-state
	AuthCodeUserDeleted = "AUTH_USER_DELETED" // valid token but user record no longer exists
	AuthCodeUserCheckFailed = "AUTH_USER_CHECK_FAILED" // userChecker.UserExists returned an error

	// Authorization (role)
	AuthCodeAdminRequired = "AUTH_ADMIN_REQUIRED" // valid auth but role != admin
	AuthCodeAuthRequired  = "AUTH_AUTH_REQUIRED"  // no auth at all on a protected route
)

// AuthCodedError satisfies CodedHTTPError so CanonicalEchoErrorHandler
// lands the typed `code` + user-friendly `message` in the canonical
// envelope. Mirrors AuthErrorBody from kielo-auth-service/internal/
// handlers/error_codes.go — they could de-dupe into a shared type in
// a future sweep (Sweep ZZZZ candidate: `kielo-shared/errors`).
type AuthCodedError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

func (e AuthCodedError) HTTPErrorCode() string    { return e.ErrorCode }
func (e AuthCodedError) HTTPErrorMessage() string { return e.Message }

// authErr wraps a (status, code, message) tuple into an echo.HTTPError
// the canonical handler unpacks via the CodedHTTPError interface.
func authErr(status int, code, message string) *echo.HTTPError {
	return echo.NewHTTPError(status, AuthCodedError{ErrorCode: code, Message: message})
}

// classifyJWTError inspects a jwt.ParseWithClaims error and returns
// the (code, message) tuple that best describes the failure mode.
// Mobile branches on the code:
//
//   AUTH_TOKEN_EXPIRED          → attempt silent refresh
//   AUTH_TOKEN_SIGNATURE_INVALID → force re-login (token was tampered)
//   AUTH_TOKEN_ISSUER_INVALID   → force re-login (wrong env / dev token)
//   AUTH_TOKEN_MALFORMED        → force re-login (corrupt storage)
//   AUTH_TOKEN_CLAIMS_INVALID   → force re-login (server-side bug or schema change)
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
