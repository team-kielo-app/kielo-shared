// Arc G1 (2026-06-08): typed-vocabulary SoT for
// `InAppNudgeAnchorTarget` — the canonical NAV-BAR-ANCHOR enum used
// by Loop G per
// `docs/architecture/learning-architecture-reform.md` §6.7.
//
// Each nudge points at a specific nav-bar tab (or the whole nav bar).
// Mobile uses `TutorialContext.measureTarget(<registered_id>)` to
// resolve the anchor coordinates at render time — same primitive the
// existing onboarding TutorialTooltip uses, already wired for every
// tab by both `FloatingTabBar.tsx` (phone) and `SideNavBar.tsx`
// (tablet/desktop) via `NavigationItem.tsx:71-75,222-231`.
//
// **No coordinate brittleness**: `measureTarget()` returns live
// coordinates async; no hardcoded pixel positions. Quick-feature slot
// swap (news/ktv/juka) preserves the stable `tab-quick-feature` id
// across swaps.
//
// 19th typed-vocab SoT module in kielo-shared/vocab/ (after
// inappnudgetype + inappnudgecontext + 16 prior instances).
//
// Cross-language Python mirror at
// `kielo-shared/kielo_shared/vocab/in_app_nudge_anchor_target.py`.
// Contract test at
// `tests/contract/in_app_nudge_anchor_target_vocabulary_contract_test.go`
// pins SoT non-empty + Go↔Python parity. NOT pinned against a DB
// CHECK constraint — anchor_target is NOT persisted in
// `users.in_app_nudge_state` (it's wire-shape only; reconstituted
// server-side per nudge_type via the canonical mapping in
// engine `InAppNudgeAuthor` classes).
//
// **Cardinality discipline rule**: every new InAppNudgeAnchorTarget
// value MUST correspond to a tab that's actually registered by
// `NavigationItem.tsx` on BOTH bars (or be explicitly device-class-
// scoped). Hard cap 8 anchor targets. The `tab-settings` value is
// desktop-only (SideNavBar mounts it; FloatingTabBar filters
// `isTabItem: false` items out).
package vocab

// InAppNudgeAnchorTarget is the canonical anchor surface for the
// mobile NavBarNudge component. Each value maps to a single
// `TutorialContext.registerTarget` ID.
type InAppNudgeAnchorTarget string

// String returns the wire string. Server emits this in the nudge
// response payload; mobile maps it back to the registered ID via
// `narrowAnchorTarget()` (Sweep JJJJJ Omit + intersection pattern at
// the typed-enum-narrowing layer).
func (a InAppNudgeAnchorTarget) String() string { return string(a) }

// Canonical InAppNudgeAnchorTarget vocabulary (6 values).
//
// Mapping to mobile `TutorialContext` registered IDs:
//
//	navbar           → 'navbar' (whole nav bar — used for non-specific
//	                   "discovery" nudges that don't point at one tab)
//	tab_home         → 'tab-index' (note: id is 'index' not 'home' —
//	                   asymmetry documented at recon)
//	tab_quick_feature → 'tab-quick-feature' (stable across the
//	                    news/ktv/juka swap; consumer cross-checks
//	                    `useLastUsedFeature()` against any
//	                    requiredFeatureType filter)
//	tab_exercises    → 'tab-exercises' (the roadmap tab in code)
//	tab_profile      → 'tab-profile'
//	tab_settings     → 'tab-settings' (DESKTOP-ONLY — SideNavBar
//	                   mounts; FloatingTabBar filters out)
const (
	// InAppNudgeAnchorTargetNavbar — whole nav bar. Used when no
	// specific tab is the "right" anchor (e.g. discovery_browse
	// context nudges that broadly say "look around").
	InAppNudgeAnchorTargetNavbar InAppNudgeAnchorTarget = "navbar"

	// InAppNudgeAnchorTargetTabHome — home tab. Note the wire string
	// uses `tab_home` for symmetry with the rest of the enum; mobile
	// maps to the registered ID `tab-index` (legacy asymmetry —
	// see `kielo-app/src/constants/navigation.tsx`).
	InAppNudgeAnchorTargetTabHome InAppNudgeAnchorTarget = "tab_home"

	// InAppNudgeAnchorTargetTabQuickFeature — the dynamic
	// quick-feature slot. Renders as news/ktv/juka per
	// `useLastUsedFeature()`. The ID is stable across swaps; nudges
	// targeting this slot can optionally carry a
	// `required_feature_type` filter (news|ktv|juka) — mobile
	// suppresses the nudge if the current quick-feature doesn't match.
	InAppNudgeAnchorTargetTabQuickFeature InAppNudgeAnchorTarget = "tab_quick_feature"

	// InAppNudgeAnchorTargetTabExercises — the roadmap/exercises tab.
	// Used by review_backlog_idle (DC FAB is reached via this tab).
	InAppNudgeAnchorTargetTabExercises InAppNudgeAnchorTarget = "tab_exercises"

	// InAppNudgeAnchorTargetTabProfile — the profile tab.
	InAppNudgeAnchorTargetTabProfile InAppNudgeAnchorTarget = "tab_profile"

	// InAppNudgeAnchorTargetTabSettings — DESKTOP-ONLY. SideNavBar
	// mounts; FloatingTabBar filters out via `isTabItem: false`.
	// Engine MUST suppress nudges with this anchor for phone users
	// (per device-class detection at the request layer).
	InAppNudgeAnchorTargetTabSettings InAppNudgeAnchorTarget = "tab_settings"
)

// AllInAppNudgeAnchorTargets is the canonical iteration order.
var AllInAppNudgeAnchorTargets = []InAppNudgeAnchorTarget{
	InAppNudgeAnchorTargetNavbar,
	InAppNudgeAnchorTargetTabHome,
	InAppNudgeAnchorTargetTabQuickFeature,
	InAppNudgeAnchorTargetTabExercises,
	InAppNudgeAnchorTargetTabProfile,
	InAppNudgeAnchorTargetTabSettings,
}

// IsValidInAppNudgeAnchorTarget reports whether the given value is a
// known canonical anchor target. Producers MUST call this at
// nudge-author construction time.
func IsValidInAppNudgeAnchorTarget(a InAppNudgeAnchorTarget) bool {
	switch a {
	case InAppNudgeAnchorTargetNavbar,
		InAppNudgeAnchorTargetTabHome,
		InAppNudgeAnchorTargetTabQuickFeature,
		InAppNudgeAnchorTargetTabExercises,
		InAppNudgeAnchorTargetTabProfile,
		InAppNudgeAnchorTargetTabSettings:
		return true
	}
	return false
}

// AnchorTargetToTutorialID maps the wire-shape canonical name to the
// mobile-side TutorialContext registered ID. Mobile uses this at
// render time. Centralized here so the mapping is the single SoT
// (vs duplicating in mobile code + engine code).
//
// Engine doesn't actually USE this mapping at runtime (engine emits
// canonical wire values); it's here for documentation + for the
// contract test to verify the asymmetry stays documented.
func AnchorTargetToTutorialID(a InAppNudgeAnchorTarget) string {
	switch a {
	case InAppNudgeAnchorTargetNavbar:
		return "navbar"
	case InAppNudgeAnchorTargetTabHome:
		return "tab-index" // legacy asymmetry: registered as 'tab-index' not 'tab-home'
	case InAppNudgeAnchorTargetTabQuickFeature:
		return "tab-quick-feature"
	case InAppNudgeAnchorTargetTabExercises:
		return "tab-exercises"
	case InAppNudgeAnchorTargetTabProfile:
		return "tab-profile"
	case InAppNudgeAnchorTargetTabSettings:
		return "tab-settings"
	}
	return ""
}
