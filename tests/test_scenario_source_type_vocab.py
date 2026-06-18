"""Regression tests for kielo_shared.vocab.scenario_source_type
Python mirror of kielo-shared/vocab/scenariosourcetype.go.

Sweep ZQ Gap 3 (2026-06-03): pins cardinality + wire-string format +
validator behavior.
"""

from __future__ import annotations

import pytest

from kielo_shared.vocab.scenario_source_type import (
    ALL_SCENARIO_SOURCE_TYPES,
    SCENARIO_SOURCE_TYPE_ADMIN_AUTHORED,
    SCENARIO_SOURCE_TYPE_AI_CONCEPT_HUB_V1,
    SCENARIO_SOURCE_TYPE_AI_SCENARIO_TEMPLATE_V1,
    SCENARIO_SOURCE_TYPE_EXTERNAL_IMPORTED,
    SCENARIO_SOURCE_TYPE_UNKNOWN,
    is_valid_scenario_source_type,
)


def test_cardinality_pins_five() -> None:
    """The Python mirror must declare exactly 5 values (matches Go
    SoT + V084 CHECK). Growth must be lockstep-updated across all 3
    anchors."""
    assert len(ALL_SCENARIO_SOURCE_TYPES) == 5


def test_canonical_wire_strings() -> None:
    """Wire strings must be byte-equivalent to V084 CHECK constraint
    values + Go SoT."""
    assert SCENARIO_SOURCE_TYPE_AI_CONCEPT_HUB_V1 == "ai_concept_hub_v1"
    assert SCENARIO_SOURCE_TYPE_ADMIN_AUTHORED == "admin_authored"
    assert SCENARIO_SOURCE_TYPE_AI_SCENARIO_TEMPLATE_V1 == "ai_scenario_template_v1"
    assert SCENARIO_SOURCE_TYPE_EXTERNAL_IMPORTED == "external_imported"
    assert SCENARIO_SOURCE_TYPE_UNKNOWN == "unknown"


def test_all_constants_in_iteration_container() -> None:
    """Every declared constant must appear in ALL_SCENARIO_SOURCE_TYPES
    (the iteration order used by the cross-language parity gate)."""
    declared = {
        SCENARIO_SOURCE_TYPE_AI_CONCEPT_HUB_V1,
        SCENARIO_SOURCE_TYPE_ADMIN_AUTHORED,
        SCENARIO_SOURCE_TYPE_AI_SCENARIO_TEMPLATE_V1,
        SCENARIO_SOURCE_TYPE_EXTERNAL_IMPORTED,
        SCENARIO_SOURCE_TYPE_UNKNOWN,
    }
    assert declared == ALL_SCENARIO_SOURCE_TYPES


@pytest.mark.parametrize(
    "wire,expected",
    [
        ("ai_concept_hub_v1", True),
        ("admin_authored", True),
        ("ai_scenario_template_v1", True),
        ("external_imported", True),
        ("unknown", True),
        ("AI_CONCEPT_HUB_V1", False),  # canonical wire is lowercase snake
        ("ai_concept_hub", False),  # missing version suffix
        ("ai_concept_hub_v2", False),  # not yet defined
        ("", False),
        ("admin", False),  # truncated
        ("AdminAuthored", False),  # PascalCase divergence
    ],
)
def test_is_valid_scenario_source_type(wire: str, expected: bool) -> None:
    """Validator accepts canonical values + rejects drift cases."""
    assert is_valid_scenario_source_type(wire) is expected
