// deprecation.go: marks v1 routes that have a v3 successor with the
// IETF Deprecation + Sunset + Link rel="successor-version" headers so
// clients can detect and migrate off them.
//
// Background (ADR-004 + round 12 client migration): every kielo-app and
// kielo-admin-ui slice has migrated to /api/v3 with documented v1
// carve-outs. The remaining v1 traffic is from legacy mobile builds and
// a handful of internal admin tools. This middleware tags responses
// from v1 routes that have a known v3 mirror — once observability
// confirms the v1 call rate has tailed off, the routes can be deleted.
//
// Headers emitted on every 2xx response from a tagged v1 handler:
//   - Deprecation: true
//     IETF draft-ietf-httpapi-deprecation-header. Boolean form is the
//     simplest signal; clients/proxies that parse it just need to know
//     "this URL is going away".
//   - Sunset: <RFC 7231 IMF-fixdate>
//     RFC 8594. The wall-clock instant after which servers MAY return
//     410 Gone. Default is 90 days from server start; override via
//     DeprecationOptions.SunsetDate for a fixed cutoff.
//   - Link: </api/v3{path}>; rel="successor-version"
//     RFC 8288. Points at the v3 mirror so clients can rewrite. By
//     default the v3 path is derived by replacing the leading /api/v1
//     segment with /api/v3; pass DeprecationOptions.SuccessorPath when
//     the v3 path differs (e.g. /klearn/* → /*, /users/me/* → /me/*).
//
// Apply per-route, NOT to the whole /api/v1 group: not every v1 route
// has a v3 equivalent (e.g. /events/behavioral, /admin/users, internal
// tools). Tagging an undeprecated route would lie to clients.
//
// Streaming handlers (SSE, binary audio): the headers are written
// before the first Flush, so they ride out on the response head and
// don't interfere with the stream body.

package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// DeprecationOptions controls the headers emitted by Deprecation().
// Zero value is valid: SunsetDate defaults to 90 days from process
// start, SuccessorPath is derived by /api/v1 → /api/v3 substitution.
type DeprecationOptions struct {
	// SunsetDate is the wall-clock instant after which the route MAY
	// return 410 Gone. Format MUST be RFC 7231 IMF-fixdate when
	// rendered to the wire (we handle that). Zero value defaults to
	// 90 days after process start (calculated once at first call).
	SunsetDate time.Time
	// SuccessorPath overrides the /api/v3 path embedded in the Link
	// header. Use when the v3 mirror has a different path than the
	// v1 route — e.g. v1 /klearn/topic-lists vs v3 /topic-lists.
	// Empty string means "derive from request path by swapping
	// /api/v1 → /api/v3".
	SuccessorPath string
	// Skip lets group-level callers exempt specific routes from
	// being marked deprecated — typically v1 routes that have no
	// v3 successor (e.g. /events/behavioral) and shouldn't lie to
	// clients about a v3 mirror that doesn't exist.
	//
	// Returning true from Skip suppresses Deprecation/Sunset/Link
	// emission for that request. If nil, every request gets headers.
	Skip func(echo.Context) bool
}

// Deprecation returns Echo middleware that adds Deprecation/Sunset/Link
// headers to 2xx responses from the wrapped handler. 4xx and 5xx are
// left alone (the canonical error envelope owns those headers).
//
// Usage (per route, after handler & before any auth middleware so the
// headers ride out even on auth failures? — no, after auth so we don't
// leak the deprecation signal on 401s):
//
//	apiV1.GET("/me/notifications",
//	    handler.GetMyNotifications,
//	    middleware.Deprecation(middleware.DeprecationOptions{}))
func Deprecation(opts DeprecationOptions) echo.MiddlewareFunc {
	sunset := opts.SunsetDate
	if sunset.IsZero() {
		sunset = time.Now().Add(90 * 24 * time.Hour)
	}
	// Format once at middleware construction; it's the same string
	// for every request handled by this instance.
	sunsetHeader := sunset.UTC().Format(http.TimeFormat)
	successorOverride := opts.SuccessorPath

	skip := opts.Skip

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skip != nil && skip(c) {
				return next(c)
			}

			// Compute Link target before calling next so we can write
			// the response headers up front (matters for SSE — headers
			// flush at WriteHeader, after which we can't add more).
			successor := successorOverride
			if successor == "" {
				successor = strings.Replace(c.Request().URL.Path, "/api/v1", "/api/v3", 1)
			}

			h := c.Response().Header()
			h.Set("Deprecation", "true")
			h.Set("Sunset", sunsetHeader)
			h.Set("Link", "<"+successor+">; rel=\"successor-version\"")

			return next(c)
		}
	}
}

// LegacyAliasOptions configures LegacyAlias() — a sibling to Deprecation()
// for the v3-alias-to-canonical case (vs. v1-to-v3).
//
// Why we need a separate helper from Deprecation():
//
//	(a) The default v1→v3 path substitution doesn't apply: both alias
//	    and canonical live under /api/v3, with disjoint path shapes
//	    (e.g. /api/v3/feed → /api/v3/me/recommendations/articles).
//	    Successor MUST be supplied explicitly.
//	(b) We want a usage counter so we can tell when an alias has
//	    decayed to zero traffic and is safe to delete. Production
//	    rollback discipline says: don't delete a legacy alias until
//	    the metric stays at zero across one or two mobile-app release
//	    cycles (App Store / Play Store reviews + adoption curve).
type LegacyAliasOptions struct {
	// Service is the short name of the service emitting the metric
	// (e.g. "mobile-bff"). Must be non-empty.
	Service string
	// Successor is the canonical v3 path the alias forwards to. Must
	// be non-empty. Used both in the Link header and the metric label.
	Successor string
	// SunsetDate is the wall-clock instant after which the alias MAY
	// return 410 Gone. Zero value defaults to 90 days after process
	// start, but for alias deprecation a fixed date is preferred so
	// the headers stay stable across rolling deploys.
	SunsetDate time.Time
}

// LegacyAlias returns Echo middleware that marks a route as a v3 alias
// of a canonical v3 path. On every request it:
//
//   - increments kielo_v3_legacy_alias_hits_total{service,path,successor}
//     so a burn-down dashboard can show when usage drops to zero;
//   - sets Deprecation: true, Sunset: <RFC 7231 date>, and
//     Link: <successor>; rel="successor-version" headers on the response.
//
// The metric increment happens before the handler runs (so we count
// every request hitting the alias, including those that 4xx/5xx out).
// Headers are set before calling next so they ride out on the response
// head even for SSE / streaming handlers that flush early.
//
// Apply per-route at registration time:
//
//	v3.GET("/feed",
//	    feedHandler.GetFeed,
//	    middleware.LegacyAlias(middleware.LegacyAliasOptions{
//	        Service:    "mobile-bff",
//	        Successor:  "/api/v3/me/recommendations/articles",
//	        SunsetDate: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
//	    }))
func LegacyAlias(opts LegacyAliasOptions) echo.MiddlewareFunc {
	if opts.Service == "" || opts.Successor == "" {
		// Misconfigured callers get a no-op — preferable to a panic at
		// route registration which would take down the whole service.
		// The empty-arg case is loud enough at code review.
		return func(next echo.HandlerFunc) echo.HandlerFunc { return next }
	}
	sunset := opts.SunsetDate
	if sunset.IsZero() {
		sunset = time.Now().Add(90 * 24 * time.Hour)
	}
	sunsetHeader := sunset.UTC().Format(http.TimeFormat)
	linkHeader := "<" + opts.Successor + ">; rel=\"successor-version\""

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			sharedmetrics.LegacyAliasHitsTotal.
				WithLabelValues(opts.Service, c.Path(), opts.Successor).
				Inc()

			h := c.Response().Header()
			h.Set("Deprecation", "true")
			h.Set("Sunset", sunsetHeader)
			h.Set("Link", linkHeader)

			return next(c)
		}
	}
}
