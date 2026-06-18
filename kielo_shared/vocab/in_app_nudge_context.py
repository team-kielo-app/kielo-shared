"""kielo_shared.vocab.in_app_nudge_context — Python mirror of
kielo-shared/vocab/inappnudgecontext.go.

Arc G1 (2026-06-08): cross-language SoT for the 8 canonical
``InAppNudgeContext`` values driving Loop G nudge selection per
``docs/architecture/learning-architecture-reform.md`` §6.7.

Mobile maps current_route → context at request time; server only sees
the canonical context label. The endpoint
``GET /api/v3/me/in-app-nudges?context=<canonical>`` returns at most
ONE nudge per context.

## Why semantic context (not 1:1 route-tree mapping)

  - Aligns with ADR-011 spine event_type prefixes
  - Aligns with users.feature_usage feature names
  - Stable across mobile route refactors
  - Cardinality stays bounded (8 contexts vs ~25+ stable screens)

## Architectural shape

  - ``InAppNudgeContext`` typed alias (str newtype)
  - 8 ``Final[InAppNudgeContext]`` constants — byte-equivalent wire
    values to Go SoT
  - ``ALL_IN_APP_NUDGE_CONTEXTS`` ``FrozenSet`` iteration container
  - ``IDLE_CONTEXTS`` / ``SESSION_CONTEXTS`` FrozenSet partitions
  - ``is_valid_in_app_nudge_context(c)`` validator helper

18th typed-vocab SoT instance in kielo-shared.
"""

from __future__ import annotations

from typing import Final, FrozenSet

# ----------------------------------------------------------------------
# Typed alias
# ----------------------------------------------------------------------

InAppNudgeContext = str

# ----------------------------------------------------------------------
# Canonical InAppNudgeContext vocabulary (8 values).
# 3 'idle' tab contexts + 5 'session' contexts.
# ----------------------------------------------------------------------

# --- Idle contexts (user between activities) ---

IN_APP_NUDGE_CONTEXT_HOME_IDLE: Final[InAppNudgeContext] = "home_idle"
"""/(main)/(tabs)/index — home tab (deprioritized post-Arc-1A but
still the cold-boot fallback for some users). Best moment to surface
'you have N reviews waiting' or 'try a scenario'."""

IN_APP_NUDGE_CONTEXT_ROADMAP_IDLE: Final[InAppNudgeContext] = "roadmap_idle"
"""/(main)/(tabs)/roadmap — the exercises tab in code. User is
browsing curriculum. Best moment for completionist nudges +
scenario-first-time prompts."""

IN_APP_NUDGE_CONTEXT_PROFILE_IDLE: Final[InAppNudgeContext] = "profile_idle"
"""/(main)/(tabs)/profile or /(main)/settings/*. User is in
account-management mode. Limited nudge surface."""

# --- Session contexts (user mid-content) ---

IN_APP_NUDGE_CONTEXT_READING_SESSION: Final[InAppNudgeContext] = "reading_session"
"""Article reader screen. Maps to ADR-011 article.* prefix +
time_spent:reading feature."""

IN_APP_NUDGE_CONTEXT_VIDEO_SESSION: Final[InAppNudgeContext] = "video_session"
"""KTV/tv player screens. Maps to ADR-011 video.* prefix +
kielotv_watch_seconds feature."""

IN_APP_NUDGE_CONTEXT_CONVERSATION_SESSION: Final[InAppNudgeContext] = (
    "conversation_session"
)
"""conversation-intro / conversation-session / conversation-transcript
screens. Maps to ADR-011 conversation.* prefix +
convo_seconds_daily feature."""

IN_APP_NUDGE_CONTEXT_EXERCISE_SESSION: Final[InAppNudgeContext] = "exercise_session"
"""Daily challenge / lesson player / custom deck. Loop B in-progress;
cross-feature nudges generally suppressed here."""

IN_APP_NUDGE_CONTEXT_DISCOVERY_BROWSE: Final[InAppNudgeContext] = "discovery_browse"
"""Saved-items, learning-items list, concept-hub list, search, news
category browse. User is exploring without committing. Generally
permissive nudge surface."""

# ----------------------------------------------------------------------
# Iteration containers
# ----------------------------------------------------------------------

IDLE_CONTEXTS: Final[FrozenSet[InAppNudgeContext]] = frozenset(
    {
        IN_APP_NUDGE_CONTEXT_HOME_IDLE,
        IN_APP_NUDGE_CONTEXT_ROADMAP_IDLE,
        IN_APP_NUDGE_CONTEXT_PROFILE_IDLE,
    }
)

SESSION_CONTEXTS: Final[FrozenSet[InAppNudgeContext]] = frozenset(
    {
        IN_APP_NUDGE_CONTEXT_READING_SESSION,
        IN_APP_NUDGE_CONTEXT_VIDEO_SESSION,
        IN_APP_NUDGE_CONTEXT_CONVERSATION_SESSION,
        IN_APP_NUDGE_CONTEXT_EXERCISE_SESSION,
        IN_APP_NUDGE_CONTEXT_DISCOVERY_BROWSE,
    }
)

ALL_IN_APP_NUDGE_CONTEXTS: Final[FrozenSet[InAppNudgeContext]] = (
    IDLE_CONTEXTS | SESSION_CONTEXTS
)
"""All canonical InAppNudgeContext wire values. The cross-language
parity contract test asserts equality with ``AllInAppNudgeContexts``
from the Go SoT."""

# ----------------------------------------------------------------------
# Validator
# ----------------------------------------------------------------------


def is_valid_in_app_nudge_context(c: object) -> bool:
    """Return True iff ``c`` is a known canonical InAppNudgeContext.
    Mirror of ``vocab.IsValidInAppNudgeContext`` in Go.
    """
    return isinstance(c, str) and c in ALL_IN_APP_NUDGE_CONTEXTS


__all__ = [
    "InAppNudgeContext",
    "IN_APP_NUDGE_CONTEXT_HOME_IDLE",
    "IN_APP_NUDGE_CONTEXT_ROADMAP_IDLE",
    "IN_APP_NUDGE_CONTEXT_PROFILE_IDLE",
    "IN_APP_NUDGE_CONTEXT_READING_SESSION",
    "IN_APP_NUDGE_CONTEXT_VIDEO_SESSION",
    "IN_APP_NUDGE_CONTEXT_CONVERSATION_SESSION",
    "IN_APP_NUDGE_CONTEXT_EXERCISE_SESSION",
    "IN_APP_NUDGE_CONTEXT_DISCOVERY_BROWSE",
    "IDLE_CONTEXTS",
    "SESSION_CONTEXTS",
    "ALL_IN_APP_NUDGE_CONTEXTS",
    "is_valid_in_app_nudge_context",
]
