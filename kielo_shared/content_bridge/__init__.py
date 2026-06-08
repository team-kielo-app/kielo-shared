"""kielo_shared.content_bridge — Python client + types for the
Content Bridge Arc 1 reader endpoint owned by kielo-content-service.

Content Bridge answers "where else has this learner encountered this
word/concept?" across articles, KTV captions, scenarios, and exercise
prompts. See docs/architecture/content-bridge-design.md.

This package re-exports the typed `ContentBridgeSurfaceType` SoT from
kielo_shared.vocab.content_bridge_surface_type so consumers can import
both the vocabulary AND the client from one location::

    from kielo_shared.content_bridge import (
        ContentBridgeClient,
        SurfaceReference,
        SURFACE_ARTICLE,
        SURFACE_VIDEO_CAPTION,
    )

Arc 1 producer + consumer status:

  - articles + video_caption → populated end-to-end via existing
    cms_<lang>.occurrences ingest pipeline. Bridge readers receive
    real rows TODAY.
  - scenario + exercise_prompt → junction tables exist (V114 + V009)
    but no producer writes them in Arc 1. Bridge readers receive
    empty results for these surfaces until Arcs 2+3 wire producers.
"""

from kielo_shared.vocab.content_bridge_surface_type import (
    ALL_CONTENT_BRIDGE_SURFACE_TYPES,
    SURFACE_ARTICLE,
    SURFACE_EXERCISE_PROMPT,
    SURFACE_SCENARIO,
    SURFACE_VIDEO_CAPTION,
    ContentBridgeSurfaceType,
    is_valid_content_bridge_surface_type,
)

from .client import (
    ContentBridgeClient,
    SurfaceReference,
    SurfacesPage,
)

__all__ = [
    # SoT re-exports
    "ContentBridgeSurfaceType",
    "SURFACE_ARTICLE",
    "SURFACE_VIDEO_CAPTION",
    "SURFACE_SCENARIO",
    "SURFACE_EXERCISE_PROMPT",
    "ALL_CONTENT_BRIDGE_SURFACE_TYPES",
    "is_valid_content_bridge_surface_type",
    # Client + response shapes
    "ContentBridgeClient",
    "SurfaceReference",
    "SurfacesPage",
]
