package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// UserExistenceChecker interface for validating user existence
type UserExistenceChecker interface {
	UserExists(ctx context.Context, userID uuid.UUID) (bool, error)
}

// Claims represents the JWT claims structure.
//
// JSON-tag policy for each field — DO NOT bulk-remove omitempty:
//
//   - UserID: required on every token; no omitempty (would marshal as
//     the zero UUID if accidentally unset, which we want to surface).
//   - Email: legitimately empty for SSO/broker logins that haven't
//     received an email scope. omitempty only affects marshaling
//     (smaller JWT body); consumers that gate on email must check
//     for empty string explicitly.
//   - Role: legitimately empty for anonymous tokens and pre-RBAC
//     legacy tokens. Admin-gating consumers compare against "admin"
//     so empty correctly fails the check. omitempty is safe.
//   - DeviceToken: legitimately empty for web sessions (admin-ui) —
//     only mobile clients populate it. omitempty is correct.
//   - LearningLanguage: NOT omitempty by design (ADR-001 strict
//     learning-language contract). Empty here is always a bug —
//     either a user signed up before the contract or onboarding
//     never completed. Empty issuance is metered via
//     LanguageDefaultFallbackTotal so we can refuse it once the
//     metric reads zero across a release cycle. Restoring omitempty
//     here would silently hide that incident class.
type Claims struct {
	UserID           uuid.UUID `json:"user_id"`
	Email            string    `json:"email,omitempty"`
	Role             string    `json:"role,omitempty"`
	DeviceToken      string    `json:"device_token,omitempty"`
	LearningLanguage string    `json:"learning_language_code"`
	jwt.RegisteredClaims
}

// JWTAuth validates JWT tokens for direct API calls
func JWTAuth(jwtSecret string, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return JWTAuthWithOptions(jwtSecret, userChecker, nil)
}

// JWTAuthWithRSA validates JWT tokens using RSA public key
func JWTAuthWithRSA(publicKeyPEM string, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return JWTAuthWithOptions("", userChecker, &JWTOptions{
		PublicKeyPEM: publicKeyPEM,
		StoreAsUser:  true,
	})
}

// JWTAuthWithRSAPublicKey validates JWT tokens using parsed RSA public key
func JWTAuthWithRSAPublicKey(publicKey *rsa.PublicKey, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return JWTAuthWithOptions("", userChecker, &JWTOptions{
		PublicKey:   publicKey,
		StoreAsUser: true,
	})
}

// JWTOptions configures JWT validation behavior
type JWTOptions struct {
	PublicKeyPEM string         // For RSA validation (PEM string)
	PublicKey    *rsa.PublicKey // For RSA validation (parsed key)
	StoreAsUser  bool           // If true, stores entire claims as "user", otherwise individual fields
}

// JWTAuthWithOptions validates JWT tokens with configurable options
func JWTAuthWithOptions(jwtSecret string, userChecker UserExistenceChecker, options *JWTOptions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// SECURITY (S4, sweep 2026-07-06): the previously-trusted
			// `x-apigateway-api-userinfo` header path was REMOVED. It parsed
			// an UNSIGNED JSON claims blob — including `role` — straight into
			// the request identity whenever a valid X-Internal-API-Key was
			// present. No component anywhere in the fleet ever SET that header
			// (the external LB is a plain HTTPS LB, not an API Gateway, and
			// does not strip client-supplied copies), so on internet-facing
			// services it was pure attack surface: anyone holding the single
			// shared internal key could forge `role:admin` for any user_id.
			// Identity now comes ONLY from a signature-verified JWT (below) or
			// the explicit X-User-ID service handshake in FlexibleAuthWithOptions.

			// Bearer token parsing (signature-verified).
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				// Sweep ZZZZ: dedicated AUTH_TOKEN_MISSING (was default
				// UNAUTHORIZED + "Missing authorization header"). Mobile
				// branches on this to silently retry-after-refresh.
				return authErr(http.StatusUnauthorized, AuthCodeTokenMissing,
					"You need to be signed in to continue.")
			}

			tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
			if !ok {
				// Sweep ZZZZ: pre-ZZZZ returned 400 + BAD_REQUEST on bad
				// bearer prefix (per RFC 6750 this should be 401). Now:
				// 401 + AUTH_TOKEN_MALFORMED so the client treats it as
				// "force re-login" not "fix your request".
				return authErr(http.StatusUnauthorized, AuthCodeTokenMalformed,
					"Your session token format is invalid. Please log in again.")
			}

			keyFunc := func(token *jwt.Token) (any, error) {
				// If RSA public key is provided, use it
				if options != nil && (options.PublicKeyPEM != "" || options.PublicKey != nil) {
					// Ensure the token is signed with an RSA algorithm
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v, expected RSA", token.Header["alg"])
					}
					if options.PublicKey != nil {
						return options.PublicKey, nil
					}
					return jwt.ParseRSAPublicKeyFromPEM([]byte(options.PublicKeyPEM))
				}
				// Otherwise, fall back to the symmetric secret
				if jwtSecret != "" {
					// Ensure the token is signed with an HMAC algorithm
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v, expected HMAC", token.Header["alg"])
					}
					return []byte(jwtSecret), nil
				}
				// If neither is configured, it's a server error
				return nil, errors.New("JWT secret or public key is not configured")
			}

			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc,
				jwt.WithIssuer("kielo.app"),
				jwt.WithLeeway(1*time.Minute))

			if err != nil {
				// Sweep ZZZZ: classify the failure mode so the client can
				// differentiate "token expired → silent refresh" from
				// "signature invalid → force re-login" from "malformed →
				// corrupt storage → force re-login". Pre-ZZZZ all four
				// collapsed to "Invalid token" with default UNAUTHORIZED.
				code, message := classifyJWTError(err)
				c.Logger().Debugf("JWT middleware parse failed: code=%s err=%v", code, err)
				return authErr(http.StatusUnauthorized, code, message)
			}

			if claims, ok := token.Claims.(*Claims); ok && token.Valid {
				// Check user existence if checker provided
				if userChecker != nil {
					exists, err := userChecker.UserExists(c.Request().Context(), claims.UserID)
					if err != nil {
						c.Logger().Errorf("JWT middleware userChecker failed: %v", err)
						return authErr(http.StatusInternalServerError, AuthCodeUserCheckFailed,
							"Unable to verify your account right now. Please try again in a moment.")
					}
					if !exists {
						return authErr(http.StatusUnauthorized, AuthCodeUserDeleted,
							"Your account is no longer available. Please contact support if this is unexpected.")
					}
				}

				// Set claims in context
				setClaimsInContext(c, *claims, options)
				return next(c)
			}

			return authErr(http.StatusUnauthorized, AuthCodeTokenClaimsInvalid,
				"Your session token is missing required information. Please log in again.")
		}
	}
}

// setClaimsInContext sets claims in the echo context based on options
func setClaimsInContext(c echo.Context, claims Claims, options *JWTOptions) {
	if options != nil && options.StoreAsUser {
		// Store entire claims object as "user" (for auth-service compatibility)
		c.Set("user", &claims)
	} else {
		// Store individual fields (default behavior)
		c.Set("userID", claims.UserID)
		c.Set("userEmail", claims.Email)
		c.Set("deviceToken", claims.DeviceToken)
		// Also expose role under a stable key. Handlers that need to
		// authorize cross-user reads (e.g. an admin reading another
		// user's profile) read this without having to switch the
		// service-wide storage shape.
		c.Set("userRole", claims.Role)
	}
	// Always expose the learning language claim under the canonical key so
	// active_language.DefaultExtractor (and any other consumer) can read it
	// regardless of which storage shape the service chose above.
	if claims.LearningLanguage != "" {
		c.Set(JWTClaimKey, claims.LearningLanguage)
	}
}

// GatewayAuth trusts headers forwarded by the API gateway instead
// of re-validating JWT.
//
// DEAD CODE NOTE (2026-05-29): this function has zero callers in
// the monorepo. It encodes a planned future gateway-fronted topology
// (Cloudflare / GCP LB stamps the X-User-* headers based on the JWT
// it verified) that hasn't shipped. The X-User-Email / X-Device-Token
// reads at lines below assume those headers are populated by the
// gateway; today nothing in the monorepo sets X-User-Email
// (diag-header-drift.py flags this as GET-only), so a real call
// would extract empty strings.
//
// Kept as-is rather than deleted because (a) the upstream contract
// is documented in the function shape, and (b) ripping it out forces
// a contract re-design if the gateway topology ever ships. Mark for
// deletion at Phase 8 if the gateway topology is decisively
// abandoned.
func GatewayAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !hasValidInternalAPIKey(c.Request()) {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid internal API key")
			}
			userIDStr := c.Request().Header.Get("X-User-ID")
			if userIDStr == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing user context from gateway")
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID format")
			}

			// Set user context from gateway headers. X-User-Email
			// / X-Device-Token are stamped by the gateway in the
			// planned topology; in the current direct-JWT topology
			// they're empty (see DEAD CODE NOTE above).
			c.Set("userID", userID)
			c.Set("userEmail", c.Request().Header.Get("X-User-Email"))
			c.Set("deviceToken", c.Request().Header.Get("X-Device-Token"))
			return next(c)
		}
	}
}

// JWTAuthSimple is a convenience wrapper for JWTAuth without user checking
func JWTAuthSimple(jwtSecret string) echo.MiddlewareFunc {
	return JWTAuth(jwtSecret, nil)
}

// JWTAuthSimpleRSA is a convenience wrapper for RSA JWT auth without user checking
func JWTAuthSimpleRSA(publicKeyPEM string) echo.MiddlewareFunc {
	return JWTAuthWithRSA(publicKeyPEM, nil)
}

// JWTAuthSimpleWithUserStorage is a convenience wrapper for JWT auth that stores claims as "user"
func JWTAuthSimpleWithUserStorage(jwtSecret string) echo.MiddlewareFunc {
	return JWTAuthWithOptions(jwtSecret, nil, &JWTOptions{StoreAsUser: true})
}

// JWTAuthSimpleRSAWithUserStorage is a convenience wrapper for RSA JWT auth that stores claims as "user"
func JWTAuthSimpleRSAWithUserStorage(publicKeyPEM string) echo.MiddlewareFunc {
	return JWTAuthWithOptions("", nil, &JWTOptions{
		PublicKeyPEM: publicKeyPEM,
		StoreAsUser:  true,
	})
}

// FlexibleAuthSimple is a convenience wrapper for FlexibleAuth without user checking
func FlexibleAuthSimple(jwtSecret string) echo.MiddlewareFunc {
	return FlexibleAuth(jwtSecret, nil)
}

// FlexibleAuth supports both gateway headers and direct JWT validation
func FlexibleAuth(jwtSecret string, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return FlexibleAuthWithOptions(jwtSecret, userChecker, nil)
}

// FlexibleAuthRSA supports both gateway headers and RSA JWT validation
func FlexibleAuthRSA(publicKeyPEM string, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return FlexibleAuthWithOptions("", userChecker, &JWTOptions{
		PublicKeyPEM: publicKeyPEM,
	})
}

// FlexibleAuthWithRSAPublicKey supports both gateway headers and RSA JWT validation using parsed key
func FlexibleAuthWithRSAPublicKey(publicKey *rsa.PublicKey, userChecker UserExistenceChecker) echo.MiddlewareFunc {
	return FlexibleAuthWithOptions("", userChecker, &JWTOptions{
		PublicKey: publicKey,
	})
}

// FlexibleAuthSimpleRSA is a convenience wrapper for FlexibleAuthRSA without user checking
func FlexibleAuthSimpleRSA(publicKeyPEM string) echo.MiddlewareFunc {
	return FlexibleAuthRSA(publicKeyPEM, nil)
}

// FlexibleAuthSimpleWithRSAPublicKey is a convenience wrapper for FlexibleAuthWithRSAPublicKey without user checking
func FlexibleAuthSimpleWithRSAPublicKey(publicKey *rsa.PublicKey) echo.MiddlewareFunc {
	return FlexibleAuthWithRSAPublicKey(publicKey, nil)
}

// FlexibleAuthWithRSAPublicKeyAndStorage supports RSA JWT validation with user storage (required for RequireAdminRole)
func FlexibleAuthWithRSAPublicKeyAndStorage(publicKey *rsa.PublicKey) echo.MiddlewareFunc {
	return FlexibleAuthWithOptions("", nil, &JWTOptions{
		PublicKey:   publicKey,
		StoreAsUser: true,
	})
}

// FlexibleAuthRSAWithUserStorage supports both gateway headers and RSA JWT validation with user storage
func FlexibleAuthRSAWithUserStorage(publicKeyPEM string) echo.MiddlewareFunc {
	return FlexibleAuthWithOptions("", nil, &JWTOptions{
		PublicKeyPEM: publicKeyPEM,
		StoreAsUser:  true,
	})
}

// FlexibleAuthWithOptions supports both gateway headers and JWT validation with options
func FlexibleAuthWithOptions(jwtSecret string, userChecker UserExistenceChecker, options *JWTOptions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Try gateway headers first (preferred for internal calls)
			if userIDStr := c.Request().Header.Get("X-User-ID"); userIDStr != "" && hasValidInternalAPIKey(c.Request()) {
				userID, err := uuid.Parse(userIDStr)
				if err != nil {
					// Sweep ZZZZ: typed code; the gateway sent a non-UUID
					// X-User-ID — internal infra bug or bad upstream call.
					c.Logger().Warnf("FlexibleAuth: invalid X-User-ID format: %v", err)
					return authErr(http.StatusUnauthorized, AuthCodeTokenClaimsInvalid,
						"Your session token is missing required information. Please log in again.")
				}
				// Check user existence if checker provided
				if userChecker != nil {
					exists, err := userChecker.UserExists(c.Request().Context(), userID)
					if err != nil {
						c.Logger().Errorf("FlexibleAuth userChecker failed: %v", err)
						return authErr(http.StatusInternalServerError, AuthCodeUserCheckFailed,
							"Unable to verify your account right now. Please try again in a moment.")
					}
					if !exists {
						return authErr(http.StatusUnauthorized, AuthCodeUserDeleted,
							"Your account is no longer available. Please contact support if this is unexpected.")
					}
				}
				// Set context based on options
				if options != nil && options.StoreAsUser {
					// Create claims object for consistency
					claims := Claims{
						UserID:      userID,
						Email:       c.Request().Header.Get("X-User-Email"),
						Role:        c.Request().Header.Get("X-User-Role"),
						DeviceToken: c.Request().Header.Get("X-Device-Token"),
					}
					c.Set("user", &claims)
				} else {
					c.Set("userID", userID)
					c.Set("userEmail", c.Request().Header.Get("X-User-Email"))
					c.Set("deviceToken", c.Request().Header.Get("X-Device-Token"))
				}
				return next(c)
			}

			// Fall back to JWT validation for direct API calls
			return JWTAuthWithOptions(jwtSecret, userChecker, options)(next)(c)
		}
	}
}

// RequireAdminRole middleware checks if authenticated user has admin role
// Must be used after JWT authentication middleware
// Allows internal API key requests (they're trusted service-to-service calls)
func RequireAdminRole() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Allow internal API key requests (marked by hybridAuthMiddleware)
			// These are trusted service-to-service calls
			if isInternal, ok := c.Get("internal_request").(bool); ok && isInternal {
				return next(c)
			}

			// Get claims from context (set by JWT middleware with StoreAsUser: true)
			userInterface := c.Get("user")
			if userInterface != nil {
				claims, ok := userInterface.(*Claims)
				if ok {
					// Check for admin role
					if claims.Role == "admin" {
						return next(c)
					}
					// Sweep ZZZZ: dedicated AUTH_ADMIN_REQUIRED code so
					// admin-ui can render "your account does not have
					// admin access" instead of generic "forbidden".
					return authErr(http.StatusForbidden, AuthCodeAdminRequired,
						"This area requires administrator access.")
				}
			}

			// Check for userRole context key (set by custom middleware)
			if role, ok := c.Get("userRole").(string); ok {
				if role == "admin" {
					return next(c)
				}
				return authErr(http.StatusForbidden, AuthCodeAdminRequired,
					"This area requires administrator access.")
			}

			// Sweep ZZZZ: dedicated AUTH_AUTH_REQUIRED so client can
			// distinguish "no auth at all" from "auth but wrong role".
			return authErr(http.StatusUnauthorized, AuthCodeAuthRequired,
				"You need to be signed in to continue.")
		}
	}
}

func hasValidInternalAPIKey(r *http.Request) bool {
	expected := os.Getenv("KIELO_INTERNAL_API_KEY")
	if expected == "" {
		return false
	}
	provided := r.Header.Get(InternalAPIKeyHeader)
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
