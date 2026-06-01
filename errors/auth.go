package errors

// Auth-namespace codes — consolidated central SoT for the
// AUTH_*-prefixed wire strings emitted by kielo-shared/middleware/
// JWT chain + kielo-auth-service handlers + kielo-mobile-bff
// passthrough + consumed by kielo-app/admin-ui authErrors typed
// unions.
//
// Pre-DDDDD these were split across THREE files:
//
//   - kielo-shared/middleware/auth_codes.go  (11 codes, Sweep ZZZZ)
//     Token lifecycle + user state + role classification.
//     Emitted by JWTAuthWithOptions, FlexibleAuthWithOptions,
//     RequireAdminRole.
//
//   - kielo-auth-service/internal/handlers/error_codes.go (22 codes)
//     Login / register / refresh / reset / verify / logout handler
//     failure modes. Emitted by the 8 AuthHandler methods.
//
//   - kielo-auth-service/internal/domain/models.go         (3 codes)
//     Success codes for MessageResponse (password reset sent /
//     done, reset token valid).
//
// Sweep DDDDD ships them all here as typed Code values. Existing
// declarations in those 3 files become typed aliases pointing at
// these constants for 1 release cycle (back-compat); a follow-up
// sweep can retire the aliases after consumer migration.
//
// Cross-language mirror: kielo-app's `AuthErrorCode` union at
// kielo-app/src/features/auth/authErrors.ts:30-66 must include
// every constant declared here (the AUTH_USER_DELETED /
// AUTH_USER_CHECK_FAILED / AUTH_AUTH_REQUIRED codes are middleware-
// only but mobile branches on them). kielo-admin-ui's
// `AdminAuthErrorCode` at kielo-admin-ui/src/store/authErrors.ts:27-60
// is a subset (admins don't see verification flows).

// Token lifecycle — emitted by kielo-shared/middleware JWT chain.
const (
	CodeAuthTokenMissing          Code = "AUTH_TOKEN_MISSING"
	CodeAuthTokenMalformed        Code = "AUTH_TOKEN_MALFORMED"
	CodeAuthTokenExpired          Code = "AUTH_TOKEN_EXPIRED"
	CodeAuthTokenSignatureInvalid Code = "AUTH_TOKEN_SIGNATURE_INVALID"
	CodeAuthTokenIssuerInvalid    Code = "AUTH_TOKEN_ISSUER_INVALID"
	CodeAuthTokenClaimsInvalid    Code = "AUTH_TOKEN_CLAIMS_INVALID"
	CodeAuthSessionInvalid        Code = "AUTH_SESSION_INVALID"
)

// User-state — emitted by JWT middleware when the user disappears
// between token-issue and the request, or when the user-existence
// check itself fails (transient infra).
const (
	CodeAuthUserDeleted     Code = "AUTH_USER_DELETED"
	CodeAuthUserCheckFailed Code = "AUTH_USER_CHECK_FAILED"
)

// Authorization (role) — emitted by RequireAdminRole.
const (
	CodeAuthAdminRequired Code = "AUTH_ADMIN_REQUIRED"
	CodeAuthAuthRequired  Code = "AUTH_AUTH_REQUIRED"
)

// Auth-service handler vocabulary — emitted by AuthHandler.
const (
	CodeAuthInvalidRequestFormat     Code = "AUTH_INVALID_REQUEST_FORMAT"
	CodeAuthValidationFailed         Code = "AUTH_VALIDATION_FAILED"
	CodeAuthInvalidResetToken        Code = "AUTH_INVALID_RESET_TOKEN"
	CodeAuthInvalidResetTokenEmail   Code = "AUTH_INVALID_RESET_TOKEN_EMAIL"
	CodeAuthDeviceIdentifierMissing  Code = "AUTH_DEVICE_IDENTIFIER_MISSING"
	CodeAuthInvalidCredentials       Code = "AUTH_INVALID_CREDENTIALS"
	CodeAuthEmailInUse               Code = "AUTH_EMAIL_IN_USE"
	CodeAuthRegistrationFailed       Code = "AUTH_REGISTRATION_FAILED"
	CodeAuthLoginFailed              Code = "AUTH_LOGIN_FAILED"
	CodeAuthInvalidSocialToken       Code = "AUTH_INVALID_SOCIAL_TOKEN"
	CodeAuthSocialLoginFailed        Code = "AUTH_SOCIAL_LOGIN_FAILED"
	CodeAuthForgotPasswordFailed     Code = "AUTH_FORGOT_PASSWORD_FAILED"
	CodeAuthPasswordResetFailed      Code = "AUTH_PASSWORD_RESET_FAILED"
	CodeAuthEmailVerificationFailed  Code = "AUTH_EMAIL_VERIFICATION_FAILED"
	CodeAuthInvalidVerificationToken Code = "AUTH_INVALID_VERIFICATION_TOKEN"
	CodeAuthVerificationTokenExpired Code = "AUTH_VERIFICATION_TOKEN_EXPIRED"
	CodeAuthAccountDeletionFailed    Code = "AUTH_ACCOUNT_DELETION_FAILED"
	CodeAuthLogoutFailed             Code = "AUTH_LOGOUT_FAILED"

	// Sweep ZZZZ refresh-token distinct codes (was AUTH_INVALID_CREDENTIALS
	// pre-ZZZZ which collapsed refresh failures onto the login code).
	CodeAuthRefreshTokenInvalid  Code = "AUTH_REFRESH_TOKEN_INVALID"
	CodeAuthRefreshTokenExpired  Code = "AUTH_REFRESH_TOKEN_EXPIRED"
	CodeAuthRefreshSessionFailed Code = "AUTH_REFRESH_SESSION_FAILED"
)

// Success codes — emitted via MessageResponse on forgot-password /
// reset-password / verify-reset-token success paths. Mobile +
// admin map these to localized success messages.
const (
	CodeAuthPasswordResetSent Code = "AUTH_PASSWORD_RESET_SENT"
	CodeAuthPasswordResetDone Code = "AUTH_PASSWORD_RESET_DONE"
	CodeAuthResetTokenValid   Code = "AUTH_RESET_TOKEN_VALID"
)

// AllAuthErrorCodes is the iteration order for the central SoT —
// used by the contract test to enforce mobile + admin client
// vocabulary parity. When adding a new code, append here AND ship
// matching entries in:
//
//   - kielo-app/src/features/auth/authErrors.ts (AUTH_ERROR_KEYS + union)
//   - kielo-admin-ui/src/store/authErrors.ts (ADMIN_AUTH_MESSAGES + union)
//   - kielo-app/src/lib/localization/keys.ts (i18n key matching the code)
//
// Order: token lifecycle → user state → role → handler vocabulary.
// Helps catch missing entries in a code review.
var AllAuthErrorCodes = []Code{
	// Token lifecycle
	CodeAuthTokenMissing,
	CodeAuthTokenMalformed,
	CodeAuthTokenExpired,
	CodeAuthTokenSignatureInvalid,
	CodeAuthTokenIssuerInvalid,
	CodeAuthTokenClaimsInvalid,
	CodeAuthSessionInvalid,
	// User state
	CodeAuthUserDeleted,
	CodeAuthUserCheckFailed,
	// Role
	CodeAuthAdminRequired,
	CodeAuthAuthRequired,
	// Handler vocabulary
	CodeAuthInvalidRequestFormat,
	CodeAuthValidationFailed,
	CodeAuthInvalidResetToken,
	CodeAuthInvalidResetTokenEmail,
	CodeAuthDeviceIdentifierMissing,
	CodeAuthInvalidCredentials,
	CodeAuthEmailInUse,
	CodeAuthRegistrationFailed,
	CodeAuthLoginFailed,
	CodeAuthInvalidSocialToken,
	CodeAuthSocialLoginFailed,
	CodeAuthForgotPasswordFailed,
	CodeAuthPasswordResetFailed,
	CodeAuthEmailVerificationFailed,
	CodeAuthInvalidVerificationToken,
	CodeAuthVerificationTokenExpired,
	CodeAuthAccountDeletionFailed,
	CodeAuthLogoutFailed,
	CodeAuthRefreshTokenInvalid,
	CodeAuthRefreshTokenExpired,
	CodeAuthRefreshSessionFailed,
}

// AllAuthSuccessCodes — same iteration discipline for success codes.
var AllAuthSuccessCodes = []Code{
	CodeAuthPasswordResetSent,
	CodeAuthPasswordResetDone,
	CodeAuthResetTokenValid,
}
