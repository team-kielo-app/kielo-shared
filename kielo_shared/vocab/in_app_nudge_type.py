"""kielo_shared.vocab.in_app_nudge_type — Python mirror of
kielo-shared/vocab/inappnudgetype.go.

Arc G1 (2026-06-08): cross-language SoT for the 4 canonical
``InAppNudgeType`` values used by Loop G (discovery / cross-feature
promotion) per
``docs/architecture/learning-architecture-reform.md`` §6.7.

## Architectural shape

  - ``InAppNudgeType`` typed alias (str newtype) matching Go's
    ``vocab.InAppNudgeType``
  - 4 ``Final[InAppNudgeType]`` constants — byte-equivalent wire
    values to Go SoT
  - ``ALL_IN_APP_NUDGE_TYPES`` ``FrozenSet`` iteration container
  - ``IN_APP_NUDGE_TYPE_PRIORITY_ORDER`` tuple — canonical
    priority-ordered iteration for engine InAppNudgeService
  - ``is_valid_in_app_nudge_type(t)`` validator helper

## Cross-language parity

The contract test at
``tests/contract/in_app_nudge_type_vocabulary_contract_test.go``
asserts every Go constant has a matching Python constant AND every
Python constant has a matching Go constant + V117 CHECK constraint
parity (Sweep ZK-B novel deploy-time anchor for runtime-produced
vocabularies). Bidirectional parity prevents drift in either direction.

## v1 vocabulary

4 nudge types derived empirically from 10-user recon (52.7%
population coverage in the 30-80% target band):

  try_scenarios_first_time      — Loop C entry; 13.5% of active users
  review_backlog_idle           — Loop B re-entry; 37.8% (largest)
  roadmap_completionist_explore — Loop A/C entry post-Loop-E; 16.2%
  convo_user_try_reading        — Loop F transfer entry; 8.1%

Each maps to one engine-side InAppNudgeAuthor class (Arc G2) and one
set of eligibility predicates against existing tables (none require
dead writer revival).

17th typed-vocab SoT instance in kielo-shared.
"""

from __future__ import annotations

from typing import Final, FrozenSet, Tuple

# ----------------------------------------------------------------------
# Typed alias
# ----------------------------------------------------------------------

InAppNudgeType = str

# ----------------------------------------------------------------------
# Canonical InAppNudgeType vocabulary (4 values).
# Lowercase snake_case wire format.
# ----------------------------------------------------------------------

IN_APP_NUDGE_TYPE_TRY_SCENARIOS_FIRST_TIME: Final[InAppNudgeType] = (
    "try_scenarios_first_time"
)
"""Roadmap-engaged learners with sufficient vocabulary (>=20
user_item_statuses in learning/known) who have NEVER opened scenarios.
Loop C entry nudge."""

IN_APP_NUDGE_TYPE_REVIEW_BACKLOG_IDLE: Final[InAppNudgeType] = "review_backlog_idle"
"""Learners with >=15 due reviews AND >=2 days since last review, on
a non-review surface. Loop B re-entry. Highest population coverage
(37.8% of active users)."""

IN_APP_NUDGE_TYPE_ROADMAP_COMPLETIONIST_EXPLORE: Final[InAppNudgeType] = (
    "roadmap_completionist_explore"
)
"""Learners with >=5 lessons completed AND 0 in-progress, on roadmap
tab. Surfaces 'what next' after Loop E completion."""

IN_APP_NUDGE_TYPE_CONVO_USER_TRY_READING: Final[InAppNudgeType] = (
    "convo_user_try_reading"
)
"""Scenario-engaged learners (>=2 conversations) with 0 article reads.
Loop F transfer entry."""

# ----------------------------------------------------------------------
# Iteration containers
# ----------------------------------------------------------------------

ALL_IN_APP_NUDGE_TYPES: Final[FrozenSet[InAppNudgeType]] = frozenset(
    {
        IN_APP_NUDGE_TYPE_TRY_SCENARIOS_FIRST_TIME,
        IN_APP_NUDGE_TYPE_REVIEW_BACKLOG_IDLE,
        IN_APP_NUDGE_TYPE_ROADMAP_COMPLETIONIST_EXPLORE,
        IN_APP_NUDGE_TYPE_CONVO_USER_TRY_READING,
    }
)
"""All canonical InAppNudgeType wire values. FrozenSet for membership
checks; the cross-language parity contract test asserts equality with
``AllInAppNudgeTypes`` from the Go SoT."""

IN_APP_NUDGE_TYPE_PRIORITY_ORDER: Final[Tuple[InAppNudgeType, ...]] = (
    IN_APP_NUDGE_TYPE_REVIEW_BACKLOG_IDLE,
    IN_APP_NUDGE_TYPE_ROADMAP_COMPLETIONIST_EXPLORE,
    IN_APP_NUDGE_TYPE_TRY_SCENARIOS_FIRST_TIME,
    IN_APP_NUDGE_TYPE_CONVO_USER_TRY_READING,
)
"""Canonical priority-ordered iteration for engine InAppNudgeService.
Higher priority (left) renders first when multiple nudges are eligible
for the same (user, context).

Priority rationale (highest leverage first):
  1. review_backlog_idle — actionable retention pressure
  2. roadmap_completionist_explore — clear 'what next' moment
  3. try_scenarios_first_time — exploratory; Loop C entry
  4. convo_user_try_reading — long-tail (lowest population coverage)
"""

# ----------------------------------------------------------------------
# Validator
# ----------------------------------------------------------------------


def is_valid_in_app_nudge_type(t: object) -> bool:
    """Return True iff ``t`` is a known canonical InAppNudgeType.

    Mirror of ``vocab.IsValidInAppNudgeType`` in Go. Producers + readers
    MUST call this at API boundaries before persisting OR rendering.
    Unknown values arrive when (a) mobile sends a stale enum from an
    older app version, (b) admin tooling typoes a value, (c) test
    fixtures predate a vocabulary change. Each path MUST treat unknown
    values as 'ignore + log' rather than panic.
    """
    return isinstance(t, str) and t in ALL_IN_APP_NUDGE_TYPES


__all__ = [
    "InAppNudgeType",
    "IN_APP_NUDGE_TYPE_TRY_SCENARIOS_FIRST_TIME",
    "IN_APP_NUDGE_TYPE_REVIEW_BACKLOG_IDLE",
    "IN_APP_NUDGE_TYPE_ROADMAP_COMPLETIONIST_EXPLORE",
    "IN_APP_NUDGE_TYPE_CONVO_USER_TRY_READING",
    "ALL_IN_APP_NUDGE_TYPES",
    "IN_APP_NUDGE_TYPE_PRIORITY_ORDER",
    "is_valid_in_app_nudge_type",
]
