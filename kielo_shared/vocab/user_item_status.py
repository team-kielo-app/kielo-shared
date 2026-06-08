"""kielo_shared.vocab.user_item_status — Python mirror of
kielo-shared/vocab/useritemstatus.go.

Arc 1B v2 (2026-06-07): cross-language SoT for the 4 canonical
user_item_status values written to
``klearn_<lang>.user_item_statuses.status`` by engine + user-service
producers and read by ~8 engine consumer sites.

## Architectural shape

  - ``UserItemStatus`` typed alias (str newtype) matching Go's
    ``vocab.UserItemStatus``
  - 4 ``Final[UserItemStatus]`` constants — byte-equivalent lowercase
    values to Go SoT
  - ``ALL_USER_ITEM_STATUSES`` ``FrozenSet`` iteration container
  - ``is_valid_user_item_status(s)`` validator helper
  - ``normalize_user_item_status(s)`` legacy-to-canonical mapper —
    byte-equivalent to Go's ``NormalizeUserItemStatus``

## Cross-language parity

The contract test at
``tests/contract/user_item_status_vocabulary_contract_test.go``
asserts every Go constant has a matching Python constant AND every
Python constant has a matching Go constant. Bidirectional parity
prevents drift in either direction.

## Pre-Arc-1B-v2 drift class

The status column carried 6 distinct values produced by 4 writers:
  PascalCase (engine-derived):  "Known" (218), "Learning" (1649), "Unknown" (87)
  lowercase (mobile + user-svc): "learning" (45803), "new" (9644), "mastered" (137)

98%+ lowercase. Arc 1B v1 normalized CAMModule (1 of ~8 reader sites).
Arc 1B v2 closes the structural drift class end-to-end via V116
migration (backfill + CHECK constraint) + writer normalization at
every producer.

Sweep WW / SSS-B / SSS-C / IIII / DDDDD-B3 / ZK-B canonical typed-vocab
SoT pattern, with V116 CHECK constraint as the deploy-time anchor.
16th typed-vocab SoT instance in kielo-shared/vocab/.
"""

from __future__ import annotations

from typing import Final, FrozenSet

# ----------------------------------------------------------------------
# Typed alias
# ----------------------------------------------------------------------

UserItemStatus = str

# ----------------------------------------------------------------------
# Canonical user-item-status vocabulary (4 values).
# All lowercase to match the empirical 98%+ dominant production shape.
# Three active bands by ascending learner-proficiency + one
# forward-compat slot.
# ----------------------------------------------------------------------

USER_ITEM_STATUS_UNKNOWN: Final[UserItemStatus] = "unknown"
"""Learner has not yet engaged or proficiency below 0.3."""

USER_ITEM_STATUS_LEARNING: Final[UserItemStatus] = "learning"
"""Learner has engaged (mobile tap + saved-item) or proficiency in [0.3, 0.7);
the active practice band."""

USER_ITEM_STATUS_KNOWN: Final[UserItemStatus] = "known"
"""Learner has demonstrated retention via review-outcome or proficiency ≥ 0.7."""

USER_ITEM_STATUS_IGNORED: Final[UserItemStatus] = "ignored"
"""Learner explicitly opted out of practicing this item (forward-compat;
no writer fires today)."""

# ----------------------------------------------------------------------
# Iteration container
# ----------------------------------------------------------------------

ALL_USER_ITEM_STATUSES: Final[FrozenSet[UserItemStatus]] = frozenset(
    {
        USER_ITEM_STATUS_UNKNOWN,
        USER_ITEM_STATUS_LEARNING,
        USER_ITEM_STATUS_KNOWN,
        USER_ITEM_STATUS_IGNORED,
    }
)

# ----------------------------------------------------------------------
# Validator + normalizer helpers
# ----------------------------------------------------------------------


def is_valid_user_item_status(s: str) -> bool:
    """Returns True iff s is in the closed 4-value vocabulary.

    Used by `_lint-user-item-status-vocab-coverage` (future static
    gate) to flag drift at compile time and by writer helpers that
    defensively reject unknown inputs before persisting.

    Note: legacy values "Known", "Learning", "Unknown", "new",
    "mastered" return False — they must be normalized via
    `normalize_user_item_status` first. Pre-V116 rows carrying these
    values will be backfilled by the migration; post-V116 the CHECK
    constraint rejects them.
    """
    return s in ALL_USER_ITEM_STATUSES


def normalize_user_item_status(s: str) -> UserItemStatus:
    """Maps any legacy or mixed-case status value to the canonical
    lowercase 4-value vocabulary. Returns the empty string when the
    input is empty OR cannot be mapped (caller MUST check
    is_valid_user_item_status before persisting).

    Mapping table — byte-equivalent to Go's NormalizeUserItemStatus:

      canonical (passthrough): "unknown", "learning", "known", "ignored"
      legacy PascalCase:       "Unknown" → "unknown", "Learning" → "learning",
                               "Known" → "known", "Ignored" → "ignored"
      semantic equivalents:    "new" → "unknown" (user-service SaveItem
                               historically wrote "new"),
                               "mastered" → "known" (legacy writer
                               abandoned 2025-12-25)

    V116 applies this same mapping in SQL to backfill the table before
    the CHECK constraint lands. Go + Python helpers MUST stay in
    lockstep with V116 (cross-language parity gate enforces).
    """
    if s in ("unknown", "Unknown", "new", "New"):
        return USER_ITEM_STATUS_UNKNOWN
    if s in ("learning", "Learning"):
        return USER_ITEM_STATUS_LEARNING
    if s in ("known", "Known", "mastered", "Mastered"):
        return USER_ITEM_STATUS_KNOWN
    if s in ("ignored", "Ignored"):
        return USER_ITEM_STATUS_IGNORED
    return ""


__all__ = [
    "UserItemStatus",
    "USER_ITEM_STATUS_UNKNOWN",
    "USER_ITEM_STATUS_LEARNING",
    "USER_ITEM_STATUS_KNOWN",
    "USER_ITEM_STATUS_IGNORED",
    "ALL_USER_ITEM_STATUSES",
    "is_valid_user_item_status",
    "normalize_user_item_status",
]
