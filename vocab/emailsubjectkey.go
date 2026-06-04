// Package vocab — typed-vocabulary SoT for kielo-shared.
//
// Sweep post-multibucket-arc Bucket B6 (2026-06-04). Closes design doc
// §5 Tier-1B #6: lift `email.*` registry keys to typed constants per
// the same Sweep ZK-B / Bucket-7-PushKey shape.
//
// PATTERN: identical to vocab.PushKey (kielo-shared/vocab/pushkey.go).
// Typed alias `EmailSubjectKey` over `string`; 6 typed constants; iteration
// slice + IsKnownEmailSubjectKey validator + cross-language parity test.
package vocab

// EmailSubjectKey is a typed wrapper around the email subject registry
// key. Compile-time prevents passing the wrong-shape literal at call
// sites (typo'd key prefix, key from another registry, etc.).
type EmailSubjectKey string

// String returns the wire-form registry key. Used at the
// supportregistry.MapRegistry boundary which still accepts string
// keys via supportregistry.Key conversion.
func (k EmailSubjectKey) String() string {
	return string(k)
}

// Email subject key constants. Wire strings match the pre-B6 values in
// kielo-communications-service/internal/services/email_service.go
// emailSubjectRegistry seed block. Wire format: 'ui.email.subject.<name>'.
// Lockstep: changing a wire string here is a breaking change for the
// registry seed — the cross-language parity test catches drift.
//
// Sweep post-multibucket-arc Bucket B6 (2026-06-04).
const (
	EmailSubjectKeyPasswordReset              EmailSubjectKey = "ui.email.subject.password_reset"
	EmailSubjectKeyWelcome                    EmailSubjectKey = "ui.email.subject.welcome"
	EmailSubjectKeyPurchaseConfirmation       EmailSubjectKey = "ui.email.subject.purchase_confirmation"
	EmailSubjectKeySubscriptionEnded          EmailSubjectKey = "ui.email.subject.subscription_ended"
	EmailSubjectKeyAccountDeleted             EmailSubjectKey = "ui.email.subject.account_deleted"
	EmailSubjectKeyAchievementFirstPayingUser EmailSubjectKey = "ui.email.subject.achievement_first_paying_user"
)

// AllEmailSubjectKeys is the iteration set for the email subject key
// vocabulary. Contract tests assert this slice's cardinality matches
// the registry seed block + the cross-language parity test set.
//
// Sweep post-multibucket-arc Bucket B6 (2026-06-04).
var AllEmailSubjectKeys = []EmailSubjectKey{
	EmailSubjectKeyPasswordReset,
	EmailSubjectKeyWelcome,
	EmailSubjectKeyPurchaseConfirmation,
	EmailSubjectKeySubscriptionEnded,
	EmailSubjectKeyAccountDeleted,
	EmailSubjectKeyAchievementFirstPayingUser,
}

// IsKnownEmailSubjectKey returns true when the given wire string matches a
// declared EmailSubjectKey constant. Used by contract tests + future
// static gates that detect typo'd literals at non-typed call sites.
//
// Sweep post-multibucket-arc Bucket B6 (2026-06-04).
func IsKnownEmailSubjectKey(s string) bool {
	for _, k := range AllEmailSubjectKeys {
		if k.String() == s {
			return true
		}
	}
	return false
}
