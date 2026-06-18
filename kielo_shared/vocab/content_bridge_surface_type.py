"""kielo_shared.vocab.content_bridge_surface_type — Python mirror of
kielo-shared/vocab/contentbridgesurfacetype.go.

Content Bridge Arc 1 (2026-06-07): cross-language SoT for the 4
canonical surface-type wire-string values used by the Bridge's
reader endpoint at::

    GET /internal/api/v3/content-bridge/items/{item_id}/surfaces
        ?surface_type=article,video_caption,scenario,exercise_prompt

Mirrors the Go-side typed alias + constants + iteration container at
the wire-string level.

## Architectural shape

  - ``ContentBridgeSurfaceType`` typed alias (str newtype) matching
    Go's ``vocab.ContentBridgeSurfaceType``
  - 4 ``Final[ContentBridgeSurfaceType]`` constants — byte-equivalent
    values to Go SoT
  - ``ALL_CONTENT_BRIDGE_SURFACE_TYPES`` ``FrozenSet`` iteration
    container
  - ``is_valid_content_bridge_surface_type(s)`` validator helper

## Cross-language parity

The contract test at
``tests/contract/content_bridge_surface_type_vocabulary_contract_test.go``
asserts every Go constant has a matching Python constant AND every
Python constant has a matching Go constant. Adding a new value in one
language without the other fails the gate.

## Arc 1 readiness

  - ``SURFACE_ARTICLE`` + ``SURFACE_VIDEO_CAPTION`` — populated
    end-to-end via existing ``cms_<lang>.occurrences`` writes.

  - ``SURFACE_SCENARIO`` + ``SURFACE_EXERCISE_PROMPT`` — empty
    junction tables in Arc 1; readers return ``[]`` until Arcs 2+3
    wire producers.

## Python consumer call sites (Arc 1)

  - kielolearn-engine/.../services/new_item_encountered_notification_author.py
    consumes the Bridge via the Python client (kielo_shared.content_bridge.client)
    to resolve the deep_link destination per the Sweep-MMM
    no-fallback discipline (silence is the right answer when no
    surface resolves).
"""

from __future__ import annotations

from typing import Final, FrozenSet, NewType

# Typed alias mirroring Go-side vocab.ContentBridgeSurfaceType.
ContentBridgeSurfaceType = NewType("ContentBridgeSurfaceType", str)


# Production-ready surface types (2 — populated end-to-end in Arc 1).

SURFACE_ARTICLE: Final[ContentBridgeSurfaceType] = ContentBridgeSurfaceType("article")
"""News article paragraphs. Reader reads ``cms_<lang>.occurrences``
WHERE ``source_type='article'``. Surface_id is the content_version_id;
``paragraph_id`` + ``sentence_text`` + ``original_token_phrase`` carry
the grounding snippet."""

SURFACE_VIDEO_CAPTION: Final[ContentBridgeSurfaceType] = ContentBridgeSurfaceType(
    "video_caption"
)
"""KTV video caption cues. Reader reads ``cms_<lang>.occurrences``
WHERE ``source_type='video'``. Surface_id is the content_version_id;
``caption_index`` + ``timestamp_start`` + ``sentence_text`` carry the
grounding snippet + seek target."""


# Producer-pending surface types (2 — empty junction tables in Arc 1;
# readers return [] until producers wire up).

SURFACE_SCENARIO: Final[ContentBridgeSurfaceType] = ContentBridgeSurfaceType("scenario")
"""Convo scenario turns + hints. Empty in Arc 1; producer wired in
Arc 3 (sub-recon-driven choice: post-session correction extraction
OR LLM batch annotation OR author-time annotation)."""

SURFACE_EXERCISE_PROMPT: Final[ContentBridgeSurfaceType] = ContentBridgeSurfaceType(
    "exercise_prompt"
)
"""kielolearn-engine generated exercise prompts. Empty in Arc 1;
producer wired in Arc 2 (LLM emit-time annotation at
structured_output.py persist point)."""


# Iteration container — frozenset of all 4 canonical values. Used by:
#   - The Go↔Python parity contract test.
#   - The producer-scan contract test.
#   - Operator tooling that needs to enumerate every surface type.
ALL_CONTENT_BRIDGE_SURFACE_TYPES: FrozenSet[ContentBridgeSurfaceType] = frozenset(
    {
        SURFACE_ARTICLE,
        SURFACE_VIDEO_CAPTION,
        SURFACE_SCENARIO,
        SURFACE_EXERCISE_PROMPT,
    }
)


def is_valid_content_bridge_surface_type(value: str) -> bool:
    """Return True when value is one of the canonical wire strings.

    Use this at API request-validation layers (e.g. when constructing
    a Bridge client query) to reject typo'd inputs at the application
    boundary before they hit the reader endpoint's HTTP 400.
    """
    return ContentBridgeSurfaceType(value) in ALL_CONTENT_BRIDGE_SURFACE_TYPES


__all__ = [
    "ContentBridgeSurfaceType",
    "SURFACE_ARTICLE",
    "SURFACE_VIDEO_CAPTION",
    "SURFACE_SCENARIO",
    "SURFACE_EXERCISE_PROMPT",
    "ALL_CONTENT_BRIDGE_SURFACE_TYPES",
    "is_valid_content_bridge_surface_type",
]
