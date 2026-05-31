// Package-level event-type constants for the DIRECT Pub/Sub publish
// envelope class (DISTINCT from the ADR-011 user-action spine in
// eventtype.go AND the transactional-outbox envelope in
// outboxeventtype.go).
//
// Three event-envelope classes share the kielo monorepo:
//
//   - UserActionEnvelope events (eventtype.go) are produced by the
//     mobile-bff via the events pipeline and consumed by the spine
//     (kielo-events service). Their contract is pinned by
//     tests/contract/event_vocabulary_contract_test.go.
//
//   - Outbox events (outboxeventtype.go) are produced by service
//     business txs that INSERT a row into <service>.outbox_events;
//     a per-service OutboxConsumer drains rows and republishes them
//     to Pub/Sub. Their contract is pinned by
//     tests/contract/outbox_event_vocabulary_contract_test.go
//     (added in Sweep SSS-C).
//
//   - Direct-publish events (THIS FILE) are produced inline by
//     business handlers via `pubsubClient.Publish*` calls — NO
//     outbox row, NO drainer. The handler directly publishes to a
//     Pub/Sub topic in the same goroutine that processed the request.
//     This class trades at-most-once durability (vs outbox's
//     at-least-once-with-retry) for lower latency and simpler code.
//     Most events are user-facing webhook reactions (purchase.*)
//     where the publisher SHOULD NOT block on tx commit.
//
// Pre-Sweep-IIII (this file), every direct-publish event_type was
// scattered as a raw string literal across (a) producer
// `publishEvent(..., "purchase.confirmation.v1", ...)` call sites in
// kielo-user-service/internal/pubsub/client.go, (b) consumer
// switch-case branches in
// kielo-communications-service/internal/handlers/pubsub_handler.go,
// (c) consumer-side typed constants declared independently in
// kielo-content-service/main.go, (d) a Python consumer literal in
// kielolearn-engine/src/.../worker_router.py, and (e) test
// assertions. The 7 purchase.* event_types each had 4+ duplicate
// declarations across services + languages.
//
// Sweep IIII consolidates the vocabulary here. Producers MUST pass
// these typed constants to the publishEvent helper; consumers MUST
// switch on these constants. A contract test enforces this at lint
// time.
//
// Adding a new direct-publish event_type:
//
//  1. Add the constant here with the canonical wire string.
//  2. Add the constant to AllPublishEventTypes for iteration.
//  3. Wire the producer to write the constant (NOT a raw literal).
//  4. Wire the consumer's switch-case to read the constant.
//  5. Add the Pub/Sub subscription filter to scripts/setup_pubsub_topics.sh.
//  6. If a Python consumer exists, mirror the constant in the Python
//     module that consumes the event (informational only — the static
//     gate scans Go for now).
//
// The contract test enforces (3) and (4); step (5) and (6) remain
// operator discipline.
package events

// PublishEventType is the typed alias producers pass into the
// publishEvent helper in kielo-user-service/internal/pubsub/client.go
// (and any future direct-publish call site). The wire format is a
// string so the Pub/Sub message attribute stays stable across schema
// migrations; this Go type narrows the producer-side surface so a
// stray literal can't be silently accepted.
//
// Distinct from EventType (ADR-011 spine) and OutboxEventType (this
// package, outboxeventtype.go) — the three vocabularies have disjoint
// string namespaces and disjoint consumer paths.
type PublishEventType string

// String returns the wire string. Allows the typed constant to be
// used directly in fmt.Sprintf / log fields / Pub/Sub attribute
// binding without an explicit conversion at every call site.
func (p PublishEventType) String() string {
	return string(p)
}

// Purchase events. Producer: kielo-user-service business handlers
// (RevenueCat webhook + admin grants); consumed by
// kielo-communications-service (push + email dispatch).
const (
	// EventPurchaseConfirmation fires on initial purchase / first
	// successful entitlement grant. Consumer sends
	// "subscription_active" push + welcome email.
	EventPurchaseConfirmation PublishEventType = "purchase.confirmation.v1"

	// EventPurchaseIssue fires on payment retry failures + dunning.
	// Consumer sends "payment_issue" push (informational).
	EventPurchaseIssue PublishEventType = "purchase.issue.v1"

	// EventPurchaseCancellation fires on user-initiated cancellation
	// (auto-renew off). Subscription remains active until expiry.
	// Consumer sends "cancellation_acknowledged" push.
	EventPurchaseCancellation PublishEventType = "purchase.cancellation.v1"

	// EventPurchaseRenewed fires on successful auto-renewal.
	// Consumer is silent (no push); event exists for analytics.
	EventPurchaseRenewed PublishEventType = "purchase.renewed.v1"

	// EventPurchaseUncanceled fires when a user re-enables
	// auto-renew on a previously-canceled subscription. Consumer is
	// silent (analytics).
	EventPurchaseUncanceled PublishEventType = "purchase.uncanceled.v1"

	// EventPurchaseProductChange fires on upgrade/downgrade between
	// product tiers. Consumer is silent (analytics).
	EventPurchaseProductChange PublishEventType = "purchase.product_change.v1"

	// EventPurchaseExpired fires when entitlement actually ends.
	// Consumer sends "subscription_expired" push.
	EventPurchaseExpired PublishEventType = "purchase.expired.v1"
)

// User events (direct-publish path). NOTE: user.profile.updated.v1
// and user.deleted.v1 are ALSO outbox event_types because the
// user-service writes them via outbox for durable downstream
// cascade. The direct-publish duplicates exist for legacy
// compatibility with the kielo-communications-service consumer that
// pre-dates the outbox-drainer pattern. Both producers emit the SAME
// wire string; consumers handle either path.
//
// Sweep IIII follow-up: audit whether the direct-publish path is
// still needed once SSS-C's outbox-drainer is the canonical path.
// For now, both vocabularies declare the wire string so producers
// can typed-reference whichever path they're on.
const (
	// EventUserProfileUpdatedDirect is the direct-publish mirror of
	// EventUserProfileUpdated (outboxeventtype.go). Same wire string;
	// distinct constant so the consumer can tell which producer path
	// it's on (direct vs drained-from-outbox).
	EventUserProfileUpdatedDirect PublishEventType = "user.profile.updated.v1"

	// EventUserDeletedDirect is the direct-publish mirror of
	// EventUserDeleted (outboxeventtype.go). Same wire string;
	// distinct constant for producer/consumer differentiation.
	EventUserDeletedDirect PublishEventType = "user.deleted.v1"

	// EventUserLearningItemSavedDirect is the direct-publish mirror of
	// EventUserLearningItemSaved (outboxeventtype.go). Same wire
	// string; distinct constant.
	EventUserLearningItemSavedDirect PublishEventType = "user.learning_item.saved.v1"
)

// System events (direct-publish only — no outbox mirror).
const (
	// EventSystemNotification is a generic admin-triggered direct push
	// (broadcasts, force-app-update prompts, scheduled maintenance
	// warnings). Producer: admin handler. Consumer:
	// kielo-communications-service push handler.
	EventSystemNotification PublishEventType = "system.notification.v1"
)

// AllPublishEventTypes is the canonical iteration order. Used by the
// contract test (Sweep IIII) to assert every literal in producer
// code matches a value here, and by operator tooling that needs to
// enumerate every event_type the system can directly publish.
var AllPublishEventTypes = []PublishEventType{
	EventPurchaseConfirmation,
	EventPurchaseIssue,
	EventPurchaseCancellation,
	EventPurchaseRenewed,
	EventPurchaseUncanceled,
	EventPurchaseProductChange,
	EventPurchaseExpired,
	EventUserProfileUpdatedDirect,
	EventUserDeletedDirect,
	EventUserLearningItemSavedDirect,
	EventSystemNotification,
}

// IsKnownPublishEventType returns true when s matches a canonical
// direct-publish event_type string. Useful for consumer-side
// validation of inbound Pub/Sub messages before dispatch.
func IsKnownPublishEventType(s string) bool {
	for _, e := range AllPublishEventTypes {
		if string(e) == s {
			return true
		}
	}
	return false
}
