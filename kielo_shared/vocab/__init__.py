"""kielo_shared.vocab — Python mirror of kielo-shared/vocab (Go).

Sweep ZK-B (2026-06-03): cross-language SoT for closed-vocabulary
typed aliases shared across services + Python engine. Mirrors the
Go-side ``kielo-shared/vocab`` package at the wire-string + iteration
level.

Currently re-exports:

  - ``achievement`` — 21 canonical achievement codes (Sweep ZK-B)
  - ``scenario_source_type`` — 5 canonical convo.scenarios.source_type
    wire-string values (Sweep ZQ Gap 3)

Future vocabularies (Sweep D ItemType, etc.) should be added as
sibling submodules following the same pattern.
"""
