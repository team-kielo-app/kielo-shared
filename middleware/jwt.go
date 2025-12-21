package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
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

// Claims represents the JWT claims structure
type Claims struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role,omitempty"`
	DeviceToken string    `json:"device_token,omitempty"`
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
			// Check for API Gateway user info header first (for mobile-bff compatibility)
			userInfo := c.Request().Header.Get("x-apigateway-api-userinfo")
			if userInfo != "" && hasValidInternalAPIKey(c.Request()) {
				// Parse the user info as JSON claims
				var claims Claims
				if err := json.Unmarshal([]byte(userInfo), &claims); err == nil {
					// Check user existence if checker provided
					if userChecker != nil {
						exists, err := userChecker.UserExists(c.Request().Context(), claims.UserID)
						if err != nil {
							return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user existence")
						}
						if !exists {
							return echo.NewHTTPError(http.StatusUnauthorized, "User no longer exists")
						}
					}
					// Set claims in context
					setClaimsInContext(c, claims, options)
					return next(c)
				}
			}

			// Fallback to traditional Bearer token parsing
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid authorization header format")
			}

			keyFunc := func(token *jwt.Token) (interface{}, error) {
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
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
			}

			if claims, ok := token.Claims.(*Claims); ok && token.Valid {
				// Check user existence if checker provided
				if userChecker != nil {
					exists, err := userChecker.UserExists(c.Request().Context(), claims.UserID)
					if err != nil {
						return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user existence")
					}
					if !exists {
						return echo.NewHTTPError(http.StatusUnauthorized, "User no longer exists")
					}
				}

				// Set claims in context
				setClaimsInContext(c, *claims, options)
				return next(c)
			}

			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
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
	}
}

// GatewayAuth trusts headers forwarded by the API gateway instead of re-validating JWT
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

			// Set user context from gateway headers
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
					return echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID format")
				}
				// Check user existence if checker provided
				if userChecker != nil {
					exists, err := userChecker.UserExists(c.Request().Context(), userID)
					if err != nil {
						return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user existence")
					}
					if !exists {
						return echo.NewHTTPError(http.StatusUnauthorized, "User no longer exists")
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
					return echo.NewHTTPError(http.StatusForbidden, "admin access required")
				}
			}

			// Check for userRole context key (set by custom middleware)
			if role, ok := c.Get("userRole").(string); ok {
				if role == "admin" {
					return next(c)
				}
				return echo.NewHTTPError(http.StatusForbidden, "admin access required")
			}

			// No valid authentication found
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
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
