"""Arc G1 (2026-06-08) — Python-side unit tests for the 3 in-app-nudge
typed vocabulary SoTs.

Mirror of the Sweep ZK-B + ZJ-B test shape. Cross-language parity is
covered by the Go-side contract tests at
``tests/contract/in_app_nudge_*_vocabulary_contract_test.go``; these
tests pin the Python-side invariants independently.
"""

from __future__ import annotations

import re

from kielo_shared.vocab import (
    in_app_nudge_anchor_target as anchor_mod,
    in_app_nudge_context as context_mod,
    in_app_nudge_type as type_mod,
)


# ----------------------------------------------------------------------
# InAppNudgeType (4 values)
# ----------------------------------------------------------------------


def test_in_app_nudge_type_cardinality_pinned_at_4():
    """V117 CHECK constraint pins 4 values; SoT must match exactly."""
    assert len(type_mod.ALL_IN_APP_NUDGE_TYPES) == 4


def test_in_app_nudge_type_priority_order_covers_all_types():
    """The priority-ordered tuple is the canonical iteration for the
    engine InAppNudgeService — every type must appear exactly once."""
    assert len(type_mod.IN_APP_NUDGE_TYPE_PRIORITY_ORDER) == 4
    assert set(type_mod.IN_APP_NUDGE_TYPE_PRIORITY_ORDER) == type_mod.ALL_IN_APP_NUDGE_TYPES


def test_in_app_nudge_type_priority_order_highest_first():
    """review_backlog_idle is highest-leverage (37.8% population
    coverage); should be first in priority order."""
    assert (
        type_mod.IN_APP_NUDGE_TYPE_PRIORITY_ORDER[0]
        == type_mod.IN_APP_NUDGE_TYPE_REVIEW_BACKLOG_IDLE
    )


def test_in_app_nudge_type_lowercase_snake_case():
    pattern = re.compile(r"^[a-z][a-z_0-9]*$")
    for value in type_mod.ALL_IN_APP_NUDGE_TYPES:
        assert pattern.match(value), f"{value!r} must be lowercase snake_case"


def test_in_app_nudge_type_validator_accepts_canonical():
    for value in type_mod.ALL_IN_APP_NUDGE_TYPES:
        assert type_mod.is_valid_in_app_nudge_type(value)


def test_in_app_nudge_type_validator_rejects_unknown():
    assert not type_mod.is_valid_in_app_nudge_type("synthetic_unknown_type")
    assert not type_mod.is_valid_in_app_nudge_type("")
    assert not type_mod.is_valid_in_app_nudge_type(None)
    assert not type_mod.is_valid_in_app_nudge_type(42)


# ----------------------------------------------------------------------
# InAppNudgeContext (8 values: 3 idle + 5 session)
# ----------------------------------------------------------------------


def test_in_app_nudge_context_cardinality_pinned_at_8():
    """V117 CHECK constraint pins 8 values; SoT must match exactly."""
    assert len(context_mod.ALL_IN_APP_NUDGE_CONTEXTS) == 8


def test_in_app_nudge_context_idle_session_partition():
    """3 idle + 5 session = 8 total; partitions are disjoint."""
    assert len(context_mod.IDLE_CONTEXTS) == 3
    assert len(context_mod.SESSION_CONTEXTS) == 5
    assert not (context_mod.IDLE_CONTEXTS & context_mod.SESSION_CONTEXTS)
    assert (
        context_mod.IDLE_CONTEXTS | context_mod.SESSION_CONTEXTS
        == context_mod.ALL_IN_APP_NUDGE_CONTEXTS
    )


def test_in_app_nudge_context_idle_endings():
    """All idle contexts end in `_idle`; all session contexts end in
    `_session` OR `_browse` (discovery_browse). Pinned to catch the
    case where a new value is added to the wrong partition."""
    for value in context_mod.IDLE_CONTEXTS:
        assert value.endswith("_idle"), f"{value!r} in IDLE_CONTEXTS but no _idle suffix"
    for value in context_mod.SESSION_CONTEXTS:
        assert value.endswith("_session") or value.endswith("_browse"), (
            f"{value!r} in SESSION_CONTEXTS but no _session/_browse suffix"
        )


def test_in_app_nudge_context_lowercase_snake_case():
    pattern = re.compile(r"^[a-z][a-z_0-9]*$")
    for value in context_mod.ALL_IN_APP_NUDGE_CONTEXTS:
        assert pattern.match(value), f"{value!r} must be lowercase snake_case"


def test_in_app_nudge_context_validator():
    for value in context_mod.ALL_IN_APP_NUDGE_CONTEXTS:
        assert context_mod.is_valid_in_app_nudge_context(value)
    assert not context_mod.is_valid_in_app_nudge_context("synthetic_unknown")
    assert not context_mod.is_valid_in_app_nudge_context("")
    assert not context_mod.is_valid_in_app_nudge_context(None)


# ----------------------------------------------------------------------
# InAppNudgeAnchorTarget (6 values)
# ----------------------------------------------------------------------


def test_in_app_nudge_anchor_target_cardinality_pinned_at_6():
    """6 anchor targets: navbar + 5 tab-specific."""
    assert len(anchor_mod.ALL_IN_APP_NUDGE_ANCHOR_TARGETS) == 6


def test_in_app_nudge_anchor_target_validator():
    for value in anchor_mod.ALL_IN_APP_NUDGE_ANCHOR_TARGETS:
        assert anchor_mod.is_valid_in_app_nudge_anchor_target(value)
    assert not anchor_mod.is_valid_in_app_nudge_anchor_target("tab_unknown")
    assert not anchor_mod.is_valid_in_app_nudge_anchor_target("")
    assert not anchor_mod.is_valid_in_app_nudge_anchor_target(None)


def test_in_app_nudge_anchor_target_tutorial_id_mapping():
    """Wire value → mobile TutorialContext registered id mapping.
    Note the documented asymmetry: ``tab_home`` → ``tab-index``
    (legacy id naming in `kielo-app/src/constants/navigation.tsx`).
    Every canonical wire value MUST map to a non-empty id."""
    for value in anchor_mod.ALL_IN_APP_NUDGE_ANCHOR_TARGETS:
        mapped = anchor_mod.anchor_target_to_tutorial_id(value)
        assert mapped, f"{value!r} maps to empty tutorial id"

    # Spot-check the documented legacy asymmetry.
    assert (
        anchor_mod.anchor_target_to_tutorial_id(
            anchor_mod.IN_APP_NUDGE_ANCHOR_TARGET_TAB_HOME
        )
        == "tab-index"
    )

    # Unknown values return None (callers treat as ignore).
    assert anchor_mod.anchor_target_to_tutorial_id("tab_unknown") is None


def test_in_app_nudge_anchor_target_canonical_names():
    """Spot-check the 6 canonical wire values to prevent silent
    rename drift."""
    expected = {
        "navbar",
        "tab_home",
        "tab_quick_feature",
        "tab_exercises",
        "tab_profile",
        "tab_settings",
    }
    assert anchor_mod.ALL_IN_APP_NUDGE_ANCHOR_TARGETS == expected
