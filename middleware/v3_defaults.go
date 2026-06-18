// v3_defaults.go: one-call middleware bundle for `/api/v3` groups.
//
// Per ADR-006 §5 + §4 every v3 group must mount:
//
//   - SingletonEnvelopeWrapper: ensures 2xx JSON object responses are
//     wrapped in the canonical `{"data": ...}` envelope (ADR-004 §4).
//   - PrivateNoStore: sets `Cache-Control: private, no-store` so
//     authenticated responses never leak to shared caches (ADR-006 §4).
//
// Pre-ADR-006, services mounted these middlewares individually and
// some forgot one or the other — kielo-content-service was missing
// both, kielo-user-service was missing the envelope wrapper.
//
// MountV3Defaults registers them as a single call so every new service
// gets the canonical baseline. Idempotency middleware is NOT included
// because it requires a Redis client; mount it separately when the
// service already has one (see kielo-user-service/main.go for the
// pattern).
//
// Mount order matters:
//  1. SingletonEnvelopeWrapper FIRST — it inspects the response body
//     after the handler writes it and reformats the JSON. The other
//     middlewares only set headers and don't touch the body, so order
//     vs. PrivateNoStore is functionally equivalent, but envelope-
//     first keeps the response-body chain visually grouped.
//  2. PrivateNoStore LAST — sets the Cache-Control header during the
//     pre-handler phase; it doesn't interact with the body rewriter.
//
// The function is variadic-free on purpose: opinions about additions
// belong in ADR-006, not in optional flags.

package middleware

import "github.com/labstack/echo/v4"

// MountV3Defaults registers the canonical v3 middleware bundle on g.
// Call once per v3 group (typically right after authn middleware).
//
// Usage:
//
//	apiV3 := e.Group("/api/v3", jwtMiddleware, activeLanguageMW)
//	sharedmiddleware.MountV3Defaults(apiV3)
//	// ...then register routes
//
// Idempotency middleware (requires Redis) is mounted separately:
//
//	apiV3.Use(sharedmiddleware.Idempotency(sharedmiddleware.IdempotencyOptions{
//	    Redis: redisClient,
//	}))
func MountV3Defaults(g *echo.Group) {
	g.Use(SingletonEnvelopeWrapper())
	g.Use(PrivateNoStore())
}
