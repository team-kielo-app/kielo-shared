"""kielo_shared.vocab.achievement tests — Sweep ZK-B (2026-06-03).

Mirrors the kielo_shared.errors test pattern (Sweep DDDDD-B3) and
kielo_shared.events test pattern (Sweep ZJ-B). Pins:

- Cardinality (16 canonical codes).
- Wire-string format (lowercase snake_case + optional numeric suffix).
- Helper functions behave correctly on edge cases.
"""

from __future__ import annotations

import re

import pytest

from kielo_shared.vocab import achievement


def test_cardinality_pinned_at_16():
    """The seed defines 16 canonical codes; SoT must match exactly.

    Adding a new code requires (a) V005-sibling migration, (b) new
    constant + iteration-set entry, (c) Go-side parity.
    """
    assert len(achievement.ALL_ACHIEVEMENT_CODES) == 16


def test_all_codes_are_lowercase_snake_case():
    """Pre-ZK-B drift caught: `first_login` typo at validation_test:49
    (canonical is `first_word`). Format validator catches typo class."""
    pattern = re.compile(r"^[a-z][a-z_0-9]*$")
    for code in achievement.ALL_ACHIEVEMENT_CODES:
        assert pattern.match(code), f"{code!r} must be lowercase snake_case"


def test_all_codes_unique():
    """Pinned per typed-vocab SoT pattern (DDDDD-B3 + IIII + SSS-C +
    ZJ-B): no two constants share a wire string."""
    values = [
        achievement.ACHIEVEMENT_CODE_FIRST_WORD,
        achievement.ACHIEVEMENT_CODE_WORDS_10,
        achievement.ACHIEVEMENT_CODE_WORDS_50,
        achievement.ACHIEVEMENT_CODE_WORDS_100,
        achievement.ACHIEVEMENT_CODE_WORDS_500,
        achievement.ACHIEVEMENT_CODE_FIRST_GRAMMAR,
        achievement.ACHIEVEMENT_CODE_GRAMMAR_10,
        achievement.ACHIEVEMENT_CODE_GRAMMAR_500,
        achievement.ACHIEVEMENT_CODE_EXERCISES_100,
        achievement.ACHIEVEMENT_CODE_EXERCISES_500,
        achievement.ACHIEVEMENT_CODE_EXERCISES_1000,
        achievement.ACHIEVEMENT_CODE_STREAK_3,
        achievement.ACHIEVEMENT_CODE_STREAK_7,
        achievement.ACHIEVEMENT_CODE_STREAK_30,
        achievement.ACHIEVEMENT_CODE_CONCEPT_HUB_CREATOR,
        achievement.ACHIEVEMENT_CODE_FIRST_PAYING_USER,
    ]
    assert len(set(values)) == len(values), "duplicate wire string detected"


def test_iteration_set_matches_individual_constants():
    """ALL_ACHIEVEMENT_CODES iteration container must equal the union
    of every individual constant. Catches the case where a constant is
    added but the iteration set isn't updated (silent invariant break)."""
    individual = {
        achievement.ACHIEVEMENT_CODE_FIRST_WORD,
        achievement.ACHIEVEMENT_CODE_WORDS_10,
        achievement.ACHIEVEMENT_CODE_WORDS_50,
        achievement.ACHIEVEMENT_CODE_WORDS_100,
        achievement.ACHIEVEMENT_CODE_WORDS_500,
        achievement.ACHIEVEMENT_CODE_FIRST_GRAMMAR,
        achievement.ACHIEVEMENT_CODE_GRAMMAR_10,
        achievement.ACHIEVEMENT_CODE_GRAMMAR_500,
        achievement.ACHIEVEMENT_CODE_EXERCISES_100,
        achievement.ACHIEVEMENT_CODE_EXERCISES_500,
        achievement.ACHIEVEMENT_CODE_EXERCISES_1000,
        achievement.ACHIEVEMENT_CODE_STREAK_3,
        achievement.ACHIEVEMENT_CODE_STREAK_7,
        achievement.ACHIEVEMENT_CODE_STREAK_30,
        achievement.ACHIEVEMENT_CODE_CONCEPT_HUB_CREATOR,
        achievement.ACHIEVEMENT_CODE_FIRST_PAYING_USER,
    }
    assert achievement.ALL_ACHIEVEMENT_CODES == individual


def test_validator_accepts_canonical():
    """is_valid_achievement_code accepts every registered code."""
    for code in achievement.ALL_ACHIEVEMENT_CODES:
        assert achievement.is_valid_achievement_code(code), (
            f"{code!r} should be valid"
        )


def test_validator_rejects_drift():
    """Drift cases must be rejected: typos, casing, fragments, empty."""
    rejected = [
        "streaks_3",       # plural typo (recon flagged silent-failure class)
        "first_login",     # validation_test:49 typo (drive-by fix)
        "FIRST_WORD",      # uppercase
        "First_Word",      # PascalCase
        "word_10",         # incomplete name
        "",                # empty
        "first_word.v1",   # extra suffix
        " first_word",     # leading whitespace
        "first_word ",     # trailing whitespace
        "top_learner_yearly",  # plausible but unregistered
        "top_learner_weekly",  # retired: no leaderboard ever awarded it
        "top_1_percent",       # retired: no leaderboard ever awarded it
    ]
    for s in rejected:
        assert not achievement.is_valid_achievement_code(s), (
            f"{s!r} should be rejected"
        )


@pytest.mark.parametrize(
    "code,group",
    [
        ("first_word", "word"),
        ("words_500", "word"),
        ("first_grammar", "grammar"),
        ("grammar_500", "grammar"),
        ("exercises_1000", "exercise"),
        ("streak_30", "streak"),
        ("concept_hub_creator", "special"),
        ("first_paying_user", "special"),
    ],
)
def test_canonical_code_spot_checks(code, group):
    """Spot-check that canonical wire strings recon identified are
    registered. Each parameter pair represents a different category
    documented in the SoT module."""
    assert achievement.is_valid_achievement_code(code), (
        f"{code!r} ({group}) should be in SoT"
    )
