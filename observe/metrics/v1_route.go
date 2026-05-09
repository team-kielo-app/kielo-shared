package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// V1RouteHitsTotal counts requests served by a /api/v1/* route. The
// Deprecation middleware (kielo-shared/middleware/deprecation.go) wires
// this up automatically for every v1 group, so any route under that
// group gets counted by (service, method, path-template).
//
// Use:
//   - Burn-down dashboard for the v1 → v3 sunset. A v1 route safe to
//     delete is one whose counter has been at zero over at least two
//     mobile-release cycles (App Store / Play Store distribution
//     window) — that's the bar at which we know the long tail of
//     bundled-old-build clients has decayed.
//   - Operational triage during the migration: the path label tells
//     us which clients still need a code change (admin-ui still
//     calling /api/v1/foo, or service-to-service caller).
//
// Pairs with LegacyAliasHitsTotal (kielo_v3_legacy_alias_hits_total):
// that one tracks "v3 routes renamed to canonical paths but kept as
// aliases", this one tracks "v1 routes still active during the sunset
// window". Together they're the two halves of the surface migration's
// observability story.
//
// Labels:
//   - service: short service name (e.g. "mobile-bff", "kielo-cms")
//   - method:  HTTP method ("GET", "POST", …)
//   - path:    Echo path template, e.g. "/api/v1/me/saved-items/:itemType/:itemId".
//     Echo's c.Path() returns the template (with placeholders),
//     not the resolved URL — so cardinality stays bounded by the
//     number of registered routes, not the number of UUIDs in
//     flight.
var V1RouteHitsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_v1_route_hits_total",
		Help: "Number of requests served by a /api/v1/* legacy route. " +
			"Burn down to zero (over two mobile-release cycles) before deleting the route.",
	},
	[]string{"service", "method", "path"},
)
