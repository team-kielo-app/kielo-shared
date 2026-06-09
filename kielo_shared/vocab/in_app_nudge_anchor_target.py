"""kielo_shared.vocab.in_app_nudge_anchor_target — Python mirror of
kielo-shared/vocab/inappnudgeanchortarget.go.

Arc G1 (2026-06-08): cross-language SoT for the 6 canonical
``InAppNudgeAnchorTarget`` values driving Loop G nav-bar tooltip
anchor placement per
``docs/architecture/learning-architecture-reform.md`` §6.7.

Each nudge points at a specific nav-bar tab (or the whole nav bar).
Mobile uses ``TutorialContext.measureTarget(<registered_id>)`` to
resolve the anchor coordinates at render time — same primitive the
existing onboarding TutorialTooltip uses.

NOT pinned against a DB CHECK constraint — anchor_target is NOT
persisted in users.in_app_nudge_state (it's wire-shape only;
reconstituted server-side per nudge_type via the canonical mapping in
engine InAppNudgeAuthor classes).

## Architectural shape

  - ``InAppNudgeAnchorTarget`` typed alias (str newtype)
  - 6 ``Final[InAppNudgeAnchorTarget]`` constants — byte-equivalent
    wire values to Go SoT
  - ``ALL_IN_APP_NUDGE_ANCHOR_TARGETS`` ``FrozenSet`` iteration
  - ``is_valid_in_app_nudge_anchor_target(a)`` validator
  - ``anchor_target_to_tutorial_id(a)`` mapping (server-side
    informational; mobile re-derives same mapping locally)

19th typed-vocab SoT instance in kielo-shared.
"""

from __future__ import annotations

from typing import Final, FrozenSet, Optional

# ----------------------------------------------------------------------
# Typed alias
# ----------------------------------------------------------------------

InAppNudgeAnchorTarget = str

# ----------------------------------------------------------------------
# Canonical InAppNudgeAnchorTarget vocabulary (6 values).
# ----------------------------------------------------------------------

IN_APP_NUDGE_ANCHOR_TARGET_NAVBAR: Final[InAppNudgeAnchorTarget] = "navbar"
"""Whole nav bar. Used when no specific tab is the 'right' anchor."""

IN_APP_NUDGE_ANCHOR_TARGET_TAB_HOME: Final[InAppNudgeAnchorTarget] = "tab_home"
"""Home tab. Wire string is ``tab_home`` for symmetry; mobile maps to
the registered id ``tab-index`` (legacy asymmetry — see
``kielo-app/src/constants/navigation.tsx``)."""

IN_APP_NUDGE_ANCHOR_TARGET_TAB_QUICK_FEATURE: Final[InAppNudgeAnchorTarget] = (
    "tab_quick_feature"
)
"""Dynamic quick-feature slot (news/ktv/juka per
useLastUsedFeature()). Stable across swaps."""

IN_APP_NUDGE_ANCHOR_TARGET_TAB_EXERCISES: Final[InAppNudgeAnchorTarget] = (
    "tab_exercises"
)
"""Roadmap/exercises tab. Used by review_backlog_idle (DC FAB reached
via this tab)."""

IN_APP_NUDGE_ANCHOR_TARGET_TAB_PROFILE: Final[InAppNudgeAnchorTarget] = "tab_profile"
"""Profile tab."""

IN_APP_NUDGE_ANCHOR_TARGET_TAB_SETTINGS: Final[InAppNudgeAnchorTarget] = "tab_settings"
"""DESKTOP-ONLY. SideNavBar mounts; FloatingTabBar filters out.
Engine MUST suppress nudges with this anchor for phone users."""

# ----------------------------------------------------------------------
# Iteration container
# ----------------------------------------------------------------------

ALL_IN_APP_NUDGE_ANCHOR_TARGETS: Final[FrozenSet[InAppNudgeAnchorTarget]] = frozenset(
    {
        IN_APP_NUDGE_ANCHOR_TARGET_NAVBAR,
        IN_APP_NUDGE_ANCHOR_TARGET_TAB_HOME,
        IN_APP_NUDGE_ANCHOR_TARGET_TAB_QUICK_FEATURE,
        IN_APP_NUDGE_ANCHOR_TARGET_TAB_EXERCISES,
        IN_APP_NUDGE_ANCHOR_TARGET_TAB_PROFILE,
        IN_APP_NUDGE_ANCHOR_TARGET_TAB_SETTINGS,
    }
)
"""All canonical anchor target wire values. The cross-language parity
contract test asserts equality with ``AllInAppNudgeAnchorTargets`` from
the Go SoT."""

# Map wire string -> mobile TutorialContext registered id.
# Keep in lockstep with Go's AnchorTargetToTutorialID.
_ANCHOR_TARGET_TO_TUTORIAL_ID: Final[dict] = {
    IN_APP_NUDGE_ANCHOR_TARGET_NAVBAR: "navbar",
    IN_APP_NUDGE_ANCHOR_TARGET_TAB_HOME: "tab-index",  # legacy asymmetry
    IN_APP_NUDGE_ANCHOR_TARGET_TAB_QUICK_FEATURE: "tab-quick-feature",
    IN_APP_NUDGE_ANCHOR_TARGET_TAB_EXERCISES: "tab-exercises",
    IN_APP_NUDGE_ANCHOR_TARGET_TAB_PROFILE: "tab-profile",
    IN_APP_NUDGE_ANCHOR_TARGET_TAB_SETTINGS: "tab-settings",
}

# ----------------------------------------------------------------------
# Validators + helpers
# ----------------------------------------------------------------------


def is_valid_in_app_nudge_anchor_target(a: object) -> bool:
    """Return True iff ``a`` is a known canonical anchor target.
    Mirror of ``vocab.IsValidInAppNudgeAnchorTarget`` in Go.
    """
    return isinstance(a, str) and a in ALL_IN_APP_NUDGE_ANCHOR_TARGETS


def anchor_target_to_tutorial_id(a: InAppNudgeAnchorTarget) -> Optional[str]:
    """Map wire anchor target -> mobile TutorialContext registered id.
    Mirror of Go's ``AnchorTargetToTutorialID``.

    Returns None for unknown targets (callers should treat as 'ignore').
    """
    return _ANCHOR_TARGET_TO_TUTORIAL_ID.get(a)


__all__ = [
    "InAppNudgeAnchorTarget",
    "IN_APP_NUDGE_ANCHOR_TARGET_NAVBAR",
    "IN_APP_NUDGE_ANCHOR_TARGET_TAB_HOME",
    "IN_APP_NUDGE_ANCHOR_TARGET_TAB_QUICK_FEATURE",
    "IN_APP_NUDGE_ANCHOR_TARGET_TAB_EXERCISES",
    "IN_APP_NUDGE_ANCHOR_TARGET_TAB_PROFILE",
    "IN_APP_NUDGE_ANCHOR_TARGET_TAB_SETTINGS",
    "ALL_IN_APP_NUDGE_ANCHOR_TARGETS",
    "is_valid_in_app_nudge_anchor_target",
    "anchor_target_to_tutorial_id",
]
