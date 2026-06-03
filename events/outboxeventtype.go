// Package-level event-type constants for the transactional-outbox
// envelope class (DISTINCT from the ADR-011 user-action spine in
// eventtype.go).
//
// The two envelope classes share neither vocabulary nor consumer side:
//   - UserActionEnvelope events (eventtype.go) are produced by the
//     mobile-bff via the events pipeline and consumed by the spine
//     (kielo-events service). Their contract is pinned by
//     tests/contract/event_vocabulary_contract_test.go.
//   - Outbox events (this file) are produced by service business txs
//     that INSERT a row into <service>.outbox_events; a per-service
//     OutboxConsumer drains rows and republishes them to Pub/Sub.
//     Their contract is pinned by
//     tests/contract/outbox_event_vocabulary_contract_test.go (added
//     in Sweep SSS-C).
//
// Pre-Sweep-SSS-C, every outbox event_type was scattered as a raw
// string literal across (a) producer raw-SQL INSERT statements,
// (b) producer struct-field literals on PendingOutboxEvent.EventType,
// (c) consumer switch-case branches, and (d) consumer-side typed
// constants declared independently in EACH consuming service. The
// cms.content.published.v1 / user.profile.updated.v1 strings each had
// 4+ duplicate declarations.
//
// Sweep SSS-C consolidates the vocabulary here. Producers MUST pass
// these typed constants to OutboxRepository.InsertEvent or assign them
// to PendingOutboxEvent.EventType; consumers MUST switch on these
// constants. The contract test enforces this at lint time.
//
// Adding a new outbox event_type:
//
//  1. Add the constant here with the canonical wire string.
//  2. Add the constant to AllOutboxEventTypes for iteration.
//  3. Wire the producer to write the constant (NOT a raw literal).
//  4. Wire the consumer's switch-case to read the constant.
//  5. Add the Pub/Sub subscription filter to scripts/setup_pubsub_topics.sh.
//
// The contract test enforces (3) and (4); step (5) remains operator
// discipline.
package events

// OutboxEventType is the typed alias producers pass into
// OutboxRepository.InsertEvent or assign to
// PendingOutboxEvent.EventType. The wire format is a string so the
// outbox row + Pub/Sub message attribute stay stable across schema
// migrations; this Go type narrows the producer-side surface so a
// stray literal can't be silently accepted.
//
// Distinct from EventType (ADR-011 spine) — the two vocabularies have
// disjoint string namespaces and disjoint consumer paths.
type OutboxEventType string

// String returns the wire string. Allows the typed constant to be
// used directly in fmt.Sprintf / log fields / SQL parameter binding
// without an explicit conversion at every call site.
func (o OutboxEventType) String() string {
	return string(o)
}

// CMS-side outbox events. Producer: kielo-cms business txs; written
// to cms.outbox_events.
const (
	// EventCMSContentPublished fires when an admin publishes a CMS
	// content row (article, kielotv card, scenario, daily-word).
	// Consumed by kielo-content-service (search index update),
	// kielo-communications-service (push notification dispatch),
	// kielo-user-service (badge cache invalidate).
	EventCMSContentPublished OutboxEventType = "cms.content.published.v1"

	// EventCMSContentDeleted fires when an admin deletes a published
	// CMS content row. Consumed by kielo-media-processor (asset
	// cleanup) and kielo-user-service (saved-items cascade).
	// Pre-Sweep-SSS-C, this event was DECLARED in the outbox allowlist
	// but ALL 3 production producers bypassed outbox and published
	// directly via pubsubClient.PublishContentDeleted — leaving a
	// latent at-most-once delivery gap on every delete. Sweep SSS-C
	// closes the gap by routing the publishes through outbox.
	EventCMSContentDeleted OutboxEventType = "cms.content.deleted.v1"
)

// User-service outbox events. Producer: kielo-user-service business
// txs; written to users.outbox_events.
const (
	// EventUserProfileUpdated fires when a user PATCHes their profile
	// (display_name, support_language_code, learning_language,
	// preferences, etc.). Consumed by kielo-content-service (cache
	// invalidation) and kielo-communications-service (notification
	// preference refresh).
	EventUserProfileUpdated OutboxEventType = "user.profile.updated.v1"

	// EventUserDeleted fires on hard account deletion. Consumed by
	// every downstream service for cascade cleanup.
	EventUserDeleted OutboxEventType = "user.deleted.v1"
)

// AllOutboxEventTypes is the canonical iteration order. Used by the
// contract test (Sweep SSS-C) to assert every literal in producer
// code matches a value here, and by operator tooling that needs to
// enumerate every event_type the system can emit.
var AllOutboxEventTypes = []OutboxEventType{
	EventCMSContentPublished,
	EventCMSContentDeleted,
	EventUserProfileUpdated,
	EventUserDeleted,
}

// IsKnownOutboxEventType returns true when s matches a canonical
// outbox event_type string. Useful for consumer-side validation of
// inbound Pub/Sub messages before dispatch.
func IsKnownOutboxEventType(s string) bool {
	for _, e := range AllOutboxEventTypes {
		if string(e) == s {
			return true
		}
	}
	return false
}
