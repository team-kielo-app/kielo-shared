// Package userlang declares the canonical write-source vocabulary
// for user-language-related columns. Currently covers ADR-006 Phase 5
// (users.users.support_language_source); future expansions may add
// learning_language_source if Phase 4 (per-device language) requires
// it.
//
// Sweep VVV (2026-05-31) — ADR-006 Phase 5 typed-constant SoT.
//
// Background:
// Sweep OOO surfaced the "single column serving N distinct concerns"
// defect on users.users.support_language_code — the column conflates
// (A) HTTP response language for THIS request, (B) push notification
// language for offline devices, (C) background content recommendation
// language, (D) admin support reply composition — each with different
// correct persistence model. The ADR-006 amendment's 6-phase plan
// (docs/architecture/adr-006-amendment-multi-device-language.md)
// captures the resolution.
//
// Phase 5 adds users.users.support_language_source as a tag on every
// write so readers can distinguish "user explicitly chose vi" from
// "device defaulted to vi" from "stale auto-detect snapshot from 6
// months ago".
//
// Pre-Phase-5 there were 5 documented write sources, all collapsing
// into the single column without tracking. This module declares the
// 8-value enum (5 documented + 3 reserved) backed by the V080
// migration's CHECK constraint.
//
// Sweep VVV pattern reference: this is the 6th instance of the typed-
// constant SoT pattern applied to a new vocabulary domain, mirroring
// Sweep WW (LocalizableField), Sweep SSS-A (RevocationReason), Sweep
// SSS-B (GrantSource), Sweep SSS-C (OutboxEventType), and Sweep A
// (UserActionEnvelope EventType).
//
// Adding a new SupportLanguageSource value:
//
//   1. Add the constant here with the canonical wire string.
//   2. Extend AllSupportLanguageSources for iteration.
//   3. Update the CHECK constraint in a new V0XX migration.
//   4. Update OpenAPI enum lists in docs/api/v3/openapi.json +
//      openapi-internal.json (both required fields).
//   5. Wire the new write source's call site to emit the constant.
//
// The contract test in tests/contract/
// support_language_source_vocabulary_contract_test.go enforces parity
// between (1) this file's constants, (2) the CHECK constraint values,
// and (3) the OpenAPI enum lists.
package userlang

// SupportLanguageSource is the typed alias writers pass into the
// users.users.support_language_source column. The wire format is
// a string so the column + JSON payloads stay stable across schema
// migrations; this Go type narrows the producer-side surface so a
// stray literal can't be silently accepted.
type SupportLanguageSource string

// String returns the wire string. Allows the typed constant to be
// used directly in fmt.Sprintf / log fields / SQL parameter binding
// without an explicit conversion at every call site.
func (s SupportLanguageSource) String() string {
	return string(s)
}

// Documented write sources (5 — covered by ADR-006 amendment §5.1).
const (
	// SupportLanguageSourceExplicitSettings: user tapped Settings →
	// App Language. The most authoritative source. Phase 4 push
	// handler will trust this over a stale per-device language.
	SupportLanguageSourceExplicitSettings SupportLanguageSource = "explicit_settings"

	// SupportLanguageSourceOnboardingPicker: user tapped Setup →
	// App Language during initial onboarding flow. Equally
	// authoritative as ExplicitSettings; the only difference is
	// timing.
	SupportLanguageSourceOnboardingPicker SupportLanguageSource = "onboarding_picker"

	// SupportLanguageSourceAutoDetected: useLanguageAutoDetectPrompt
	// "Allow" tap (single-shot from device locale). LESS
	// authoritative than ExplicitSettings/OnboardingPicker because
	// the value is from-device-locale-at-time-of-tap, which may
	// drift (user moves abroad, gets a new phone, etc.).
	SupportLanguageSourceAutoDetected SupportLanguageSource = "auto_detected"

	// SupportLanguageSourceSignupDefault: INSERT INTO users.users at
	// user creation with the default 'en' value. NOT authoritative;
	// represents "we had no signal at signup". Phase 6 will allow
	// readers to selectively NULL these rows.
	SupportLanguageSourceSignupDefault SupportLanguageSource = "signup_default"
)

// Historical / migration-applied sources (2 — backfilled values
// that exist in the prod data).
const (
	// SupportLanguageSourceV062Normalization: V062 fixed a 'vn' →
	// 'vi' typo on 1 row. Recorded for audit; behaves like
	// ExplicitSettings (the user had explicitly chosen vi).
	SupportLanguageSourceV062Normalization SupportLanguageSource = "v062_normalization"

	// SupportLanguageSourceV064Backfill: V064 backfilled from the
	// now-dropped device_preferences.app_language column. The
	// historical signal (was it set by tap or by another backfill?)
	// is LOST because V122 dropped the source column. Treated as
	// AutoDetected-equivalent confidence.
	SupportLanguageSourceV064Backfill SupportLanguageSource = "v064_backfill"
)

// Reserved sources (1 — placeholder for not-yet-built features).
const (
	// SupportLanguageSourceAdminOverride: reserved for a future
	// admin tool that lets support staff override a user's language
	// (e.g. to debug a stuck profile). No admin tool emits this
	// today; the enum slot is reserved per Sweep SSS-B's discipline
	// of pre-declaring near-future write sources.
	SupportLanguageSourceAdminOverride SupportLanguageSource = "admin_override"
)

// Sentinel (1 — DEFAULT for pre-Phase-5 rows).
const (
	// SupportLanguageSourceUnknown: DEFAULT. Pre-Phase-5 rows
	// backfilled via V080 carry this value because the historical
	// write source was untracked. Readers treat this as "trust value
	// as fallback, not authority" — exactly the semantics the ADR-006
	// amendment demands for pre-Phase-5 rows.
	//
	// NEW writers should NEVER emit Unknown. If you find yourself
	// reaching for it, the call site is missing a typed source —
	// add a new const above instead. The defensive fallback in the
	// repository layer (post-Sweep-VVV) silently coerces empty to
	// Unknown so the NOT NULL constraint never fires; if that
	// branch ever runs in production, it indicates a misshaped
	// writer.
	SupportLanguageSourceUnknown SupportLanguageSource = "unknown"
)

// AllSupportLanguageSources is the canonical iteration order. Used
// by:
//   - The contract test (Sweep VVV) to assert every literal in
//     producer code matches a value here.
//   - Operator tooling that needs to enumerate every source the
//     system can emit (e.g. analytics breakdown by source).
//   - The V080 CHECK constraint validation comparison.
var AllSupportLanguageSources = []SupportLanguageSource{
	SupportLanguageSourceExplicitSettings,
	SupportLanguageSourceOnboardingPicker,
	SupportLanguageSourceAutoDetected,
	SupportLanguageSourceSignupDefault,
	SupportLanguageSourceV062Normalization,
	SupportLanguageSourceV064Backfill,
	SupportLanguageSourceAdminOverride,
	SupportLanguageSourceUnknown,
}

// IsKnownSupportLanguageSource returns true when s matches a
// canonical SupportLanguageSource string. Useful for handler-side
// validation of inbound PATCH bodies before passing to the
// repository.
func IsKnownSupportLanguageSource(s string) bool {
	for _, src := range AllSupportLanguageSources {
		if string(src) == s {
			return true
		}
	}
	return false
}

// IsAuthoritative returns true for sources that represent deliberate
// user choice (ExplicitSettings, OnboardingPicker, V062Normalization,
// AdminOverride). Phase 4 push handler uses this to decide whether
// Tier-3 user-prefs win over Tier-2 per-device freshness; Phase 1/2
// mobile uses this to decide whether to seed Redux locale from a
// stale Tier-3 snapshot or to ignore it in favor of fresh Accept-
// Language.
//
// Note: AutoDetected and V064Backfill are NOT authoritative — they
// represent at-the-time-snapshot signals that may have drifted.
// SignupDefault and Unknown are likewise non-authoritative.
func (s SupportLanguageSource) IsAuthoritative() bool {
	switch s {
	case SupportLanguageSourceExplicitSettings,
		SupportLanguageSourceOnboardingPicker,
		SupportLanguageSourceV062Normalization,
		SupportLanguageSourceAdminOverride:
		return true
	default:
		return false
	}
}
