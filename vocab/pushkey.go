// Package vocab — typed-vocabulary SoT for kielo-shared.
//
// Sweep post-ZT-followup-docker Bucket 7 (2026-06-04). Per
// docs/architecture/notification-system-design.md §8 Round H Follow-up
// D.2: lift `push.*` registry keys to typed constants so:
//  1. A new locale addition can be statically checked against the
//     complete key set (no silent missing-translation drift).
//  2. A typo'd key at the call site (e.g.
//     `push.achievment.unlocked_title`) fails compile-time instead
//     of producing the raw key as the rendered push body.
//  3. Sibling SDKs (admin-ui rule-engine panel, mobile reactive UI)
//     can import the same typed vocabulary instead of re-declaring
//     strings.
//
// PATTERN: same shape as Sweep ZK-B (AchievementCode SoT) +
// Sweep WW (LocalizableField). Typed alias `PushKey` over `string`;
// 7 typed constants; iteration slice + IsKnown validator + cross-
// language parity test (Bucket 7 follow-up).
package vocab

// PushKey is a typed wrapper around the push notification registry
// key. Compile-time prevents passing the wrong-shape literal at call
// sites (typo'd key prefix, key from another registry, etc.).
type PushKey string

// String returns the wire-form registry key. Used at the
// supportregistry.MapRegistry boundary which still accepts string
// keys via supportregistry.Key conversion.
func (k PushKey) String() string {
	return string(k)
}

// Push notification key constants. Wire strings match the pre-Bucket-7
// values in kielo-communications-service/internal/handlers/pubsub_
// handler.go pushNotificationRegistry seed block. Lockstep: changing
// a wire string here is a breaking change for the registry seed —
// the V005-style cross-language parity test catches drift.
//
// Sweep post-ZT-followup-docker Bucket 7 (2026-06-04).
const (
	PushKeyPurchaseConfirmationTitle  PushKey = "push.purchase_confirmation.title"
	PushKeyPurchaseConfirmationBody   PushKey = "push.purchase_confirmation.body"
	PushKeyAchievementUnlockedTitle   PushKey = "push.achievement.unlocked_title"
	PushKeyAchievementConceptHubBody  PushKey = "push.achievement.body.concept_hub_creator"
	PushKeyAchievementFirstPayingBody PushKey = "push.achievement.body.first_paying_user"
	PushKeyAchievementGenericBody     PushKey = "push.achievement.body.generic"
	PushKeyAchievementNamedFormatBody PushKey = "push.achievement.body.named_format"
)

// FH.6 design decision: feedback voter notifications use the
// rule-engine path with translation_keys+translations DB seeding
// (V105) rather than the in-process pushNotificationRegistry. The
// vocab.PushKey alias is reserved for direct-dispatch paths
// (achievement_awarded, purchase_confirmation) where the producer
// has full data shape locally. Rule-engine templates are stored in
// localization.translation_keys with `rule.<rule_id>.title` /
// `rule.<rule_id>.body` keying. See V105 for the FH.6 seed.

// AllPushKeys is the iteration set for the push key vocabulary.
// Contract tests assert this slice's cardinality matches the registry
// seed block + the cross-language parity test set.
//
// Sweep post-ZT-followup-docker Bucket 7 (2026-06-04).
var AllPushKeys = []PushKey{
	PushKeyPurchaseConfirmationTitle,
	PushKeyPurchaseConfirmationBody,
	PushKeyAchievementUnlockedTitle,
	PushKeyAchievementConceptHubBody,
	PushKeyAchievementFirstPayingBody,
	PushKeyAchievementGenericBody,
	PushKeyAchievementNamedFormatBody,
}

// IsKnownPushKey returns true when the given wire string matches a
// declared PushKey constant. Used by contract tests + future static
// gates that detect typo'd literals at non-typed call sites.
//
// Sweep post-ZT-followup-docker Bucket 7 (2026-06-04).
func IsKnownPushKey(s string) bool {
	for _, k := range AllPushKeys {
		if k.String() == s {
			return true
		}
	}
	return false
}
