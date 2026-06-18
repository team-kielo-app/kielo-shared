package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/team-kielo-app/kielo-shared/observe/pubsubutil"
)

// PubSubAuthConfig configures the PubSubAuth middleware.
type PubSubAuthConfig struct {
	// Audience is the expected aud claim — the full URL Pub/Sub posts
	// to (e.g. https://service.run.app/internal/pubsub/events). Google's
	// validator rejects tokens whose aud doesn't match.
	Audience string

	// Skip disables verification entirely. Set via SKIP_PUBSUB_AUTH=true
	// for local/dev where Pub/Sub emulator pushes lack signed tokens;
	// must be false in production.
	Skip bool
}

// PubSubAuth returns an Echo middleware that verifies Google-issued
// Pub/Sub push tokens using pubsubutil.VerifyPubSubJWT. When Skip is
// true the middleware is a no-op (logged with a WARN once per request
// to make accidental dev-mode-in-prod misconfigurations visible).
//
// Replaces the verbatim copies that lived in main.go of every push
// consumer service (cms, content-service, user-service,
// communications-service). Centralizes the:
//   - bearer-token extraction (handles missing header, missing "Bearer "
//     prefix, and the cleaned tokenString case identically)
//   - skip-auth flag handling
//   - Google validator call
//   - 401 error response shape
//
// so that fixes to any of them apply everywhere.
func PubSubAuth(cfg PubSubAuthConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if cfg.Skip {
				log.Println("WARN: Skipping Pub/Sub auth verification (SKIP_PUBSUB_AUTH=true)")
				return next(c)
			}

			authHeader := c.Request().Header.Get("Authorization")
			tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
			if !ok || tokenString == "" {
				log.Printf("ERROR: Missing or invalid Authorization header for Pub/Sub request")
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid authorization")
			}

			if _, err := pubsubutil.VerifyPubSubJWT(c.Request().Context(), tokenString, cfg.Audience); err != nil {
				log.Printf("ERROR: Invalid JWT token for Pub/Sub request: %v", err)
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
			}
			return next(c)
		}
	}
}
