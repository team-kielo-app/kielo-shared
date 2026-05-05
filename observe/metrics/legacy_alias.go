package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// LegacyAliasHitsTotal counts requests that hit a v3 path which has been
// flagged as a legacy alias of a canonical v3 path. Used to know when a
// legacy alias is safe to delete: zero hits over a sustained window
// (typically two mobile release cycles) means clients have migrated.
//
// Why a separate metric from LanguageDefaultFallbackTotal: the alias
// signal needs different labels (path + successor) and a different
// retention/alerting story (we want a "burn-down" dashboard, not a
// regression alert).
//
// Labels:
//   - service: short service name (e.g. "mobile-bff")
//   - path: the alias path being hit (e.g. "/api/v3/feed")
//   - successor: the canonical replacement path
//     (e.g. "/api/v3/me/recommendations/articles")
var LegacyAliasHitsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_v3_legacy_alias_hits_total",
		Help: "Number of requests served by a v3 legacy-alias path. Burn down to zero before deleting the alias.",
	},
	[]string{"service", "path", "successor"},
)
