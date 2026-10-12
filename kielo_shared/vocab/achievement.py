"""kielo_shared.vocab.achievement — Python mirror of kielo-shared/vocab/achievement.go.

Sweep ZK-B (2026-06-03): cross-language SoT for the 16 canonical
achievement codes. Mirrors the Go-side typed alias + constants +
iteration container at the wire-string level.

## Architectural shape

  - ``AchievementCode`` typed alias (str newtype) matching Go's
    ``vocab.AchievementCode``
  - 16 ``Final[AchievementCode]`` constants — byte-equivalent values
    to Go SoT
  - ``ALL_ACHIEVEMENT_CODES`` ``FrozenSet`` iteration container
  - ``is_valid_achievement_code(s)`` validator helper

## Cross-language parity

The contract test at
``tests/contract/achievement_code_vocabulary_contract_test.go``
asserts every Go constant has a matching Python constant AND every
Python constant has a matching Go constant. The bidirectional parity
prevents drift in either direction; adding a new code in one language
without the other fails the gate.

## Pre-ZK-B silent-failure class

Producer typos (``streaks_3`` instead of ``streak_3``) silently
no-op'd the award:

1. engine emits the typo'd code via achievement_client.award_achievement
2. user-service handler queries achievement_definitions WHERE code = $1
3. zero rows → handler returns {awarded: false, "already_earned_or_not_found"}
4. engine's ``if result.get("awarded")`` branch is False → log.debug only
5. no Pub/Sub event, no push notification, no email, no badge in UI
6. user complains; team has no observability surface to debug

Sweep ZK-B closes this class structurally: typed constants on the
producer surface + cross-language parity gate + V005 seed parity test.
"""

from __future__ import annotations

from typing import Final, FrozenSet

# ----------------------------------------------------------------------
# Typed alias
# ----------------------------------------------------------------------

AchievementCode = str

# ----------------------------------------------------------------------
# Word-mastery achievements (5).
# Awarded by kielolearn-engine `achievement_service.py:_check_word_count`
# on every base-word save event.
# ----------------------------------------------------------------------

ACHIEVEMENT_CODE_FIRST_WORD: Final[AchievementCode] = "first_word"
ACHIEVEMENT_CODE_WORDS_10: Final[AchievementCode] = "words_10"
ACHIEVEMENT_CODE_WORDS_50: Final[AchievementCode] = "words_50"
ACHIEVEMENT_CODE_WORDS_100: Final[AchievementCode] = "words_100"
ACHIEVEMENT_CODE_WORDS_500: Final[AchievementCode] = "words_500"

# ----------------------------------------------------------------------
# Grammar-mastery achievements (3).
# Awarded by kielolearn-engine `achievement_service.py:_check_grammar_count`
# on every grammar-concept save event.
# ----------------------------------------------------------------------

ACHIEVEMENT_CODE_FIRST_GRAMMAR: Final[AchievementCode] = "first_grammar"
ACHIEVEMENT_CODE_GRAMMAR_10: Final[AchievementCode] = "grammar_10"
ACHIEVEMENT_CODE_GRAMMAR_500: Final[AchievementCode] = "grammar_500"

# ----------------------------------------------------------------------
# Exercise-completion achievements (3).
# ----------------------------------------------------------------------

ACHIEVEMENT_CODE_EXERCISES_100: Final[AchievementCode] = "exercises_100"
ACHIEVEMENT_CODE_EXERCISES_500: Final[AchievementCode] = "exercises_500"
ACHIEVEMENT_CODE_EXERCISES_1000: Final[AchievementCode] = "exercises_1000"

# ----------------------------------------------------------------------
# Streak achievements (3).
# ----------------------------------------------------------------------

ACHIEVEMENT_CODE_STREAK_3: Final[AchievementCode] = "streak_3"
ACHIEVEMENT_CODE_STREAK_7: Final[AchievementCode] = "streak_7"
ACHIEVEMENT_CODE_STREAK_30: Final[AchievementCode] = "streak_30"

# ----------------------------------------------------------------------
# Special achievements (2).
# ----------------------------------------------------------------------

ACHIEVEMENT_CODE_CONCEPT_HUB_CREATOR: Final[AchievementCode] = "concept_hub_creator"
ACHIEVEMENT_CODE_FIRST_PAYING_USER: Final[AchievementCode] = "first_paying_user"

# ----------------------------------------------------------------------
# Iteration container — frozenset for O(1) lookup, ordering-irrelevant
# (matches Go's AllAchievementCodes slice as a SET, not as an ordering).
# ----------------------------------------------------------------------

ALL_ACHIEVEMENT_CODES: Final[FrozenSet[AchievementCode]] = frozenset(
    {
        # Word mastery
        ACHIEVEMENT_CODE_FIRST_WORD,
        ACHIEVEMENT_CODE_WORDS_10,
        ACHIEVEMENT_CODE_WORDS_50,
        ACHIEVEMENT_CODE_WORDS_100,
        ACHIEVEMENT_CODE_WORDS_500,
        # Grammar mastery
        ACHIEVEMENT_CODE_FIRST_GRAMMAR,
        ACHIEVEMENT_CODE_GRAMMAR_10,
        ACHIEVEMENT_CODE_GRAMMAR_500,
        # Exercise completion
        ACHIEVEMENT_CODE_EXERCISES_100,
        ACHIEVEMENT_CODE_EXERCISES_500,
        ACHIEVEMENT_CODE_EXERCISES_1000,
        # Streak
        ACHIEVEMENT_CODE_STREAK_3,
        ACHIEVEMENT_CODE_STREAK_7,
        ACHIEVEMENT_CODE_STREAK_30,
        # Special
        ACHIEVEMENT_CODE_CONCEPT_HUB_CREATOR,
        ACHIEVEMENT_CODE_FIRST_PAYING_USER,
    }
)


def is_valid_achievement_code(s: str) -> bool:
    """Return True when ``s`` exactly matches one of the 16 canonical codes.

    Producers parsing inbound user input (admin endpoints accepting
    arbitrary ``achievement_code`` POST params) should use this to
    validate before passing to the engine emit path — protects against
    typo bleed-through at the API boundary.

    Mirrors Go ``vocab.IsValidAchievementCode``.
    """
    return s in ALL_ACHIEVEMENT_CODES


__all__ = [
    "AchievementCode",
    # Word mastery
    "ACHIEVEMENT_CODE_FIRST_WORD",
    "ACHIEVEMENT_CODE_WORDS_10",
    "ACHIEVEMENT_CODE_WORDS_50",
    "ACHIEVEMENT_CODE_WORDS_100",
    "ACHIEVEMENT_CODE_WORDS_500",
    # Grammar mastery
    "ACHIEVEMENT_CODE_FIRST_GRAMMAR",
    "ACHIEVEMENT_CODE_GRAMMAR_10",
    "ACHIEVEMENT_CODE_GRAMMAR_500",
    # Exercise completion
    "ACHIEVEMENT_CODE_EXERCISES_100",
    "ACHIEVEMENT_CODE_EXERCISES_500",
    "ACHIEVEMENT_CODE_EXERCISES_1000",
    # Streak
    "ACHIEVEMENT_CODE_STREAK_3",
    "ACHIEVEMENT_CODE_STREAK_7",
    "ACHIEVEMENT_CODE_STREAK_30",
    # Special
    "ACHIEVEMENT_CODE_CONCEPT_HUB_CREATOR",
    "ACHIEVEMENT_CODE_FIRST_PAYING_USER",
    # Iteration
    "ALL_ACHIEVEMENT_CODES",
    # Helpers
    "is_valid_achievement_code",
]
