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
)

// System events — historical, intentionally empty.
//
// Sweep post-ZT-followup-docker Round D.2 (2026-06-04) retired
// EventSystemNotification + its iteration entry + the
// handleSystemNotificationEvent consumer + Pub/Sub subscription +
// terraform filter + contract test spot-check. Sweep ZH (2026-06-03)
// established the vestigial-scaffold reframe (ZERO producers of
// system.notification.v1 in monorepo); Round D.2 completes the drain
// per ADR-006 amendment line 153 "Optional Tier-2 deferred dead-code
// drain" recommendation.
//
// If a future admin-broadcast Pub/Sub use case surfaces, the
// canonical path is a NEW event_type (e.g. admin.broadcast.v1) NOT
// resurrecting system.notification.v1 — this wire string carries
// pre-retirement semantics that would conflict with any new
// admin-broadcast design that uses NotificationRule + rule-engine
// dispatch + per-device DDDD resolver.

// Admin events (rule-engine path — NEW post-ZH guidance).
//
// Sweep post-ZT-followup-docker Round H Follow-up B (2026-06-04)
// registers admin.broadcast.v1 per the canonical replacement-path
// recommended at retirement of system.notification.v1 (Sweep ZH +
// D.2). This event_type flows through:
//
//	producer  → HTTP POST /api/v3/events/notifications
//	          (internal API key gated; admin-UI compose-broadcast
//	          panel OR scheduled job)
//	consumer  → EventHandler.HandleNotificationEvent (allowDirect=true)
//	          → looks up NotificationRule WHERE event_type=
//	          'admin.broadcast.v1' → ResolveTemplate per device
//	          language via DDDD per-token resolver → broadcast
//	          with PerDeviceContent closure (Sweep ZG canonical).
//
// Use cases:
//   - Soft-degradation maintenance banner (when backend is UP but
//     a specific feature is degraded)
//   - Admin announcement / new feature spotlight
//   - One-off operator broadcast to user cohort or all users
//
// NOT to be used for:
//   - Hard-outage maintenance blocker — use Tier M1 public GCS
//     status.json instead (Sweep H Follow-up A, shipped 2026-06-04)
//     because the GCS file must be reachable when the backend is
//     fully down.
//   - Per-user operational events (purchase / achievement) — those
//     have their own typed event_types in the purchase.* and
//     user.achievement.* namespaces.
const (
	EventAdminBroadcast            PublishEventType = "admin.broadcast.v1"
	EventAdminSubscriptionGrant    PublishEventType = "admin.subscription_grant.v1"
	EventAdminNotificationRuleEdit PublishEventType = "admin.notification_rule.edit.v1"
	// Sweep F2+F4-merged (2026-06-05): 5 sibling admin endpoints
	// extended to emit operator-action audit per Sub-agent F3.D
	// Tier-1A #1 finding. Each shares the architectural pattern
	// established by EventAdminSubscriptionGrant — typed constant
	// + V099 CHECK extension + handler.SetAuditPublisher wire +
	// emit AFTER mutation succeeds + best-effort goroutine + JWT
	// claims OR X-Admin-Operator-Id header (F3.C-fix pattern).
	EventAdminSubscriptionRevoke PublishEventType = "admin.subscription_revoke.v1"
	EventAdminAchievementAward   PublishEventType = "admin.achievement_award.v1"
	EventAdminAchievementRevoke  PublishEventType = "admin.achievement_revoke.v1"
	EventAdminFeatureLimitSet    PublishEventType = "admin.feature_limit_set.v1"
	EventAdminFeatureLimitDelete PublishEventType = "admin.feature_limit_delete.v1"
	// Sweep FF8 (2026-06-05): feature-voting moderation audit closure.
	// Pre-FF8 admin operators could change feature request status
	// (planned/in-progress/completed/rejected) + reassign category +
	// flip privacy without any audit trail anywhere (cms proxies
	// through proxyToUserService; user-service feedback_handler had
	// NO audit emit). Closes Sub-agent F-followup B Finding 2 by
	// adding the 3 missing event_types.
	EventAdminFeatureRequestStatusUpdate   PublishEventType = "admin.feature_request_status_update.v1"
	EventAdminFeatureRequestCategoryUpdate PublishEventType = "admin.feature_request_category_update.v1"
	EventAdminFeatureRequestPrivacyUpdate  PublishEventType = "admin.feature_request_privacy_update.v1"
	// Sweep FF9 (2026-06-05): recommendation campaign audit closure.
	// Pre-FF9 admin operators could create/update/delete/run-now
	// notification cohort campaigns without any audit anywhere
	// (comms-service has no local audit table — spine emit only).
	// Closes Sub-agent F-followup B Finding 3 by adding the 4
	// missing event_types.
	EventAdminRecommendationCampaignCreate PublishEventType = "admin.recommendation_campaign_create.v1"
	EventAdminRecommendationCampaignUpdate PublishEventType = "admin.recommendation_campaign_update.v1"
	EventAdminRecommendationCampaignDelete PublishEventType = "admin.recommendation_campaign_delete.v1"
	EventAdminRecommendationCampaignRunNow PublishEventType = "admin.recommendation_campaign_run_now.v1"
)

// Achievement events (direct-publish path, user-service producer).
// Sweep ZI-B.1 (2026-06-03): typed constants for previously-untyped
// wire strings surfaced by external recon (chatgpt Finding 2). The
// IIII migration drained 10 of 11 publish sites in kielo-user-service/
// internal/pubsub/client.go but missed this one. All other Publish*
// helpers in that file use sharedevents.Event*.String().
const (
	// EventUserAchievementAwarded fires when a user earns an
	// achievement. Producer: kielo-user-service achievement handler.
	// Consumer: kielo-communications-service push handler
	// (HandleAchievementAwardedEvent — Sweep OOOO PerDeviceContent
	// wired for per-device localization).
	EventUserAchievementAwarded PublishEventType = "user.achievement.awarded.v1"

	// EventUserNotificationCreated fires after a notification inbox
	// row is created. Producer: kielo-user-service notification path.
	// Consumer: kielo-communications-service notification_events.go.
	EventUserNotificationCreated PublishEventType = "user.notification.created.v1"
)

// Auth events (direct-publish path, auth-service producer).
// Sweep ZI-B.1: typed constants for previously-untyped wire strings
// emitted by kielo-auth-service. Pre-ZI all 3 were raw literals.
const (
	// EventUserPasswordResetRequested fires when a user requests a
	// password-reset email. Producer: kielo-auth-service ForgotPassword.
	// Consumer: kielo-communications-service email dispatch
	// (HandlePasswordResetEvent at pubsub_handler.go:549).
	EventUserPasswordResetRequested PublishEventType = "user.password.reset.requested.v1"

	// Sweep ZJ-A.1 (2026-06-03): EventUserAccountDeleted RETIRED.
	// The vestigial dead-emit declared on Sweep ZI-B.1 has been
	// retired end-to-end:
	//   - kielo-auth-service: publishAccountDeletedEmailEvent dropped;
	//     DeleteAccount no longer publishes.
	//   - SoT: this constant dropped; AllPublishEventTypes iteration
	//     entry dropped.
	//   - Contract tests: TestPublishEventTypeSoTNonEmpty expectedMin
	//     decremented (24 from 25; ZJ-A.2 will further decrement when
	//     EventConversationStarted retires in the same sweep).
	// When the GDPR cleanup fan-out is scoped, follow the ADR-011
	// user-action spine pattern instead of resurrecting this orphan
	// event. The pre-retirement deflection comments at
	// user_event_handler.go + pubsub_handler.go have been trimmed.

	// EventUserRegistrationConfirmed fires after a user verifies their
	// email post-registration. Producer: kielo-auth-service VerifyEmail.
	// Consumer: kielo-communications-service welcome-email dispatch
	// (HandleRegistrationEvent at pubsub_handler.go:1081) + kielo-user-
	// service post-registration provisioning hook (user_event_handler.go:59).
	EventUserRegistrationConfirmed PublishEventType = "user.registration.confirmed.v1"
)

// Content + media events (direct-publish path, cms / media-upload-api /
// media-processor producers). Sweep ZI-B.1: typed constants for the
// content + media pipeline event wire strings. Pre-ZI all raw literals.
const (
	// EventContentArticleSubmitted fires when cms creates an article
	// version pending ingest. Producer: kielo-cms article-create handler.
	// Consumer: kielo-ingest-processor (Python; subscription
	// `kielo-ingest-processor-pull-sub`).
	EventContentArticleSubmitted PublishEventType = "content.article.submitted.v1"

	// EventCMSMediaRelocate fires when cms requests media-processor to
	// move a media asset between buckets. Producer: kielo-cms. Consumer:
	// kielo-media-processor.
	EventCMSMediaRelocate PublishEventType = "cms.media.relocate.v1"

	// EventVideoCreated fires when cms creates a video content row
	// pending media-processor pipeline. Producer: kielo-cms. Consumer:
	// kielo-ingest-processor + kielo-media-processor.
	EventVideoCreated PublishEventType = "video.created.v1"

	// EventMediaUploaded fires when an upload completes + media row
	// is created. Producer: kielo-cms media-create handler (post-
	// processed upload). Consumer: kielo-media-processor.
	EventMediaUploaded PublishEventType = "media.uploaded.v1"

	// EventMediaProcessing fires when kielo-media-upload-api hands
	// off a freshly-uploaded blob to the media-processor pipeline.
	// Producer: kielo-media-upload-api. Consumer: kielo-media-processor.
	EventMediaProcessing PublishEventType = "media.processing.v1"

	// EventMediaProcessed fires when kielo-media-processor completes
	// processing (transcoding/thumbnailing/etc.). Producer:
	// kielo-media-processor. Consumer: kielo-cms + kielo-content-service.
	EventMediaProcessed PublishEventType = "media.processed.v1"
)

// CMS outbox-drained events (mirror in PublishEventType SoT so the
// kielo-cms direct-publish path can typed-reference them). These wire
// strings ALSO appear in outboxeventtype.go because the canonical
// emit path is via the outbox-drainer (Sweep SSS-C). Sweep ZI-B.1
// adds direct-publish typed mirrors for the cms/internal/pubsub/
// client.go raw literals — same Direct-suffix pattern as the
// EventUserProfileUpdatedDirect / EventUserDeletedDirect mirrors.
const (
	// EventCMSContentPublishedDirect is the direct-publish mirror of
	// EventCMSContentPublished (outboxeventtype.go). Same wire string.
	// SSS-C AGENTS row documents the known at-most-once durability gap:
	// kielo-cms emits this from internal/pubsub/client.go DIRECTLY (no
	// outbox row). When outbox-drained becomes the canonical path,
	// retire this constant.
	EventCMSContentPublishedDirect PublishEventType = "cms.content.published.v1"

	// EventCMSContentDeletedDirect is the direct-publish mirror of
	// EventCMSContentDeleted (outboxeventtype.go). Same wire string.
	// Same TTT-I durability gap as above.
	EventCMSContentDeletedDirect PublishEventType = "cms.content.deleted.v1"
)

// Sweep ZJ-A.2 (2026-06-03): EventConversationStarted RETIRED.
// The mobile-bff vestigial dead-emit declared on Sweep ZI-B.1 has
// been retired end-to-end per ADR-012 §D5 Phase 0 (line 130) +
// Phase 6 (line 368). The replacement event is the ADR-011 spine
// conversation.session_completed action emitted by the convo
// orchestrator (Phase 5 work, separate sweep). Pre-ZJ chain:
//   - kielo-mobile-bff: PublishConversationStarted method dropped;
//     ConversationStartedEvent struct dropped; conversations handler
//     no longer publishes after StartConversationSession.
//   - SoT: this constant dropped; AllPublishEventTypes iteration
//     entry dropped.
//   - Contract tests: TestPublishEventTypeSoTNonEmpty expectedMin
//     decremented to 23 (was 25; ZJ-A.1 already dropped
//     EventUserAccountDeleted).

// AllPublishEventTypes is the canonical iteration order. Used by the
// contract test (Sweep IIII) to assert every literal in producer
// code matches a value here, and by operator tooling that needs to
// enumerate every event_type the system can directly publish.
var AllPublishEventTypes = []PublishEventType{
	// Purchase events (kielo-user-service → kielo-communications-service)
	EventPurchaseConfirmation,
	EventPurchaseIssue,
	EventPurchaseCancellation,
	EventPurchaseRenewed,
	EventPurchaseUncanceled,
	EventPurchaseProductChange,
	EventPurchaseExpired,
	// User events — direct-publish mirrors of outbox events
	EventUserProfileUpdatedDirect,
	EventUserDeletedDirect,
	// System events (none — Sweep D.2 retired EventSystemNotification)
	// Admin events (Sweep Round H Follow-up B addition — rule-engine
	// path; canonical replacement for the retired system.notification.v1
	// per Sweep ZH guidance)
	EventAdminBroadcast,
	// Sweep E3 (2026-06-05): operator-action vocabulary expansion.
	// Closes D4 future-work + sub-agent B 1B.1 reframe extended
	// scope. Each operator action emits a distinct event_type via
	// the canonical admin-actions topic + AdminActionPublisher.
	EventAdminSubscriptionGrant,
	EventAdminNotificationRuleEdit,
	// Sweep F2+F4-merged additions (Sub-agent F3.D Tier-1A #1 drain)
	EventAdminSubscriptionRevoke,
	EventAdminAchievementAward,
	EventAdminAchievementRevoke,
	EventAdminFeatureLimitSet,
	EventAdminFeatureLimitDelete,
	// Sweep FF8 additions (Sub-agent F-followup B Finding 2 drain)
	EventAdminFeatureRequestStatusUpdate,
	EventAdminFeatureRequestCategoryUpdate,
	EventAdminFeatureRequestPrivacyUpdate,
	// Sweep FF9 additions (Sub-agent F-followup B Finding 3 drain)
	EventAdminRecommendationCampaignCreate,
	EventAdminRecommendationCampaignUpdate,
	EventAdminRecommendationCampaignDelete,
	EventAdminRecommendationCampaignRunNow,
	//
	// Sweep ZI-B.1 additions (chatgpt Finding 2 closure)
	EventUserAchievementAwarded,
	EventUserNotificationCreated,
	EventUserPasswordResetRequested,
	// EventUserAccountDeleted retired Sweep ZJ-A.1
	EventUserRegistrationConfirmed,
	EventContentArticleSubmitted,
	EventCMSMediaRelocate,
	EventVideoCreated,
	EventMediaUploaded,
	EventMediaProcessing,
	EventMediaProcessed,
	EventCMSContentPublishedDirect,
	EventCMSContentDeletedDirect,
	// EventConversationStarted retired Sweep ZJ-A.2
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
