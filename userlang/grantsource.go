// Sweep ZQ Gap 2 (2026-06-03) — GrantSource typed-vocab SoT lifted
// from kielo-user-service/internal/models/subscription.go to
// kielo-shared/userlang/ alongside SupportLanguageSource.
//
// Background:
// Sweep SSS-B (2026-05-30) shipped the GrantSource typed alias + 10
// constants + V076 migration backfill + CHECK constraint, but the
// SoT lived in kielo-user-service/internal/models/ rather than
// kielo-shared. That worked because user-service is the sole writer
// (subscription creation paths in subscription_service.go +
// webhook_processor.go), but it broke the typed-vocab SoT 3-anchor
// completeness invariant (Sweep ZK-B Layer 31):
//
//	(a) Producer-side closed-set scan        ✗ missing
//	(b) Go↔Python parity                     N/A (no Python writer)
//	(c) DB CHECK + OpenAPI enum parity       ✗ missing
//
// Both missing anchors stem from the typed alias living in-service:
// the contract test in tests/contract/ can't easily import
// service-local Go packages, AND the V076 CHECK has no parity test
// pinning it against the const list.
//
// Lifting to kielo-shared/userlang/ unblocks both anchors per
// Sweep VVV canonical pattern (see sources.go in this package).
// The kielo-user-service models.go file now re-exports the lifted
// constants via type aliases for back-compat with existing producer
// call sites (~6 sites) — keeps the migration surface zero-LoC at
// call sites while moving the source-of-truth.
//
// Adding a new GrantSource value:
//
//  1. Add the constant here with the canonical wire string.
//  2. Extend AllGrantSources for iteration.
//  3. Update the CHECK constraint in a new V0XX migration.
//  4. Update OpenAPI enum lists if exposing on a writable wire shape
//     (currently SubscriptionInfo is response-only; no writeable
//     enum lists today).
//  5. The contract test TestGrantSourceMatchesV076CHECK + the
//     producer scan TestGrantSourceNoStaleLiteralsInProducer enforce
//     the wiring.
package userlang

// GrantSource is the typed alias writers pass into the
// users.subscriptions.grant_source column. The wire format is a
// string so the column + JSON payloads stay stable across schema
// migrations; this Go type narrows the producer-side surface so a
// stray literal can't be silently accepted.
type GrantSource string

// String returns the wire string. Allows the typed constant to be
// used directly in fmt.Sprintf / log fields / SQL parameter binding
// without an explicit conversion at every call site.
func (g GrantSource) String() string {
	return string(g)
}

// Production write sources (4 — actively emitted by writers today).
const (
	// GrantSourceRevenueCatWebhook: INITIAL_PURCHASE event handler at
	// webhook_processor.go:662. Most common production write.
	GrantSourceRevenueCatWebhook GrantSource = "revenuecat_webhook"

	// GrantSourceAdminGrant: admin tool that grants premium tier to
	// internal testers / support cases. Emitted at
	// subscription_service.go:697 via GrantPremium.
	GrantSourceAdminGrant GrantSource = "admin_grant"

	// GrantSourceRestore: RestoreAccess paths at subscription_service.go
	// :338 + :533 — used when a user re-authenticates on a new device
	// and the existing RevenueCat purchase is re-bound.
	GrantSourceRestore GrantSource = "restore"

	// GrantSourceTransfer: future use — subscription transfer between
	// users (e.g. family plan, account merging). Reserved per
	// Sweep SSS-B's discipline of pre-declaring near-future sources.
	GrantSourceTransfer GrantSource = "transfer"
)

// Reserved sources (4 — declared per Sweep SSS-B's pre-declaration
// discipline; no writers today).
const (
	// GrantSourcePromoCode: future promo-code redemption flow.
	GrantSourcePromoCode GrantSource = "promo_code"

	// GrantSourceReferral: future referral-based grant.
	GrantSourceReferral GrantSource = "referral"

	// GrantSourceSupportComp: future support-team compensation grant
	// (distinct from admin_grant which is broader).
	GrantSourceSupportComp GrantSource = "support_comp"

	// GrantSourceBeta: future beta-program premium grant.
	GrantSourceBeta GrantSource = "beta"
)

// Historical / migration-applied (1).
const (
	// GrantSourceLegacyBackfill: V076 backfilled this value on rows
	// that pre-date the grant_source column. Treated as "trust the
	// existing entitlement but don't claim source confidence."
	GrantSourceLegacyBackfill GrantSource = "legacy_backfill"
)

// Sentinel (1 — DEFAULT for rows where the canonical source is unknown).
const (
	// GrantSourceUnknown: DEFAULT. Used by repo-layer defensive
	// fallback when a writer omits the grant_source field; this
	// should never fire in production (post-Sweep-SSS-B all writers
	// emit a typed constant).
	GrantSourceUnknown GrantSource = "unknown"
)

// AllGrantSources is the canonical iteration order. Used by:
//   - The contract test (ZQ Gap 2) to assert every literal in
//     producer code matches a value here.
//   - The CHECK-parity contract test to assert V076 CHECK matches
//     this list bidirectionally.
//   - Operator tooling that needs to enumerate every grant source
//     the system knows about.
var AllGrantSources = []GrantSource{
	GrantSourceRevenueCatWebhook,
	GrantSourceAdminGrant,
	GrantSourceRestore,
	GrantSourceTransfer,
	GrantSourcePromoCode,
	GrantSourceReferral,
	GrantSourceSupportComp,
	GrantSourceBeta,
	GrantSourceLegacyBackfill,
	GrantSourceUnknown,
}

// IsKnownGrantSource returns true when s is one of the canonical
// values. Used by repository-layer + service-layer validators to
// reject typo'd inputs at the application boundary (before they
// hit the V076 CHECK).
func IsKnownGrantSource(s GrantSource) bool {
	for _, known := range AllGrantSources {
		if known == s {
			return true
		}
	}
	return false
}
