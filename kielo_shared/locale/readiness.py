"""LanguageReadiness — the rolled-up "is this language production-ready?"
view aggregated across morphology, translation, STT, NLP, and capability
registry asset availability. Phase 13 slice 13A.

Mirrors kielo-shared/locale/readiness.go (Go). Returned by
GET /api/v3/readiness/learning-language/{code} (served by
kielo-localization). Phase 14's "selectable language" UI surface
consumes this to render the language catalog with per-language readiness
badges; ops dashboards consume the missing_assets list to triage
deploy regressions.

Design principle: per-asset signals live in each ML service's existing
/health response (morphology, translation, whisper, nlp). This shape
is a roll-up VIEW — the readiness aggregator probes those health
endpoints and synthesizes this dataclass. The aggregator does NOT
hold authoritative state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class LanguageReadiness:
    code: str
    """Normalized learning-language code (e.g. "fi", "sv")."""

    display_name: str
    """English name for UI rendering. Sourced from
    locale.language_display_name for consistency with the canonical
    multi-locale registry."""

    ready: bool
    """True if every required asset (morphology + translation to/from
    English + STT + spaCy pipeline + capability registry entry) is
    available. False if ANY required asset is missing."""

    missing_assets: Sequence[str] = field(default_factory=tuple)
    """Enumeration of absent required assets. Empty when ready=True.
    Each entry is a short asset identifier."""

    quality_tiers: Mapping[str, str] = field(default_factory=dict)
    """Per-asset quality tier (e.g. morphology="asset_backed" for
    fi-Voikko, morphology="spacy_assisted_heuristic" for sv).
    Empty values indicate the asset is unavailable."""


class LanguageReadinessProbeError(Exception):
    """Raised when a readiness probe fails to reach the underlying
    ML service. The aggregator catches this and surfaces it as an
    asset-missing entry (rather than a transport failure) so the
    readiness response stays stable even when a downstream is briefly
    unhealthy."""

    def __init__(self, asset: str, message: str) -> None:
        super().__init__(f"language-readiness probe ({asset}): {message}")
        self.asset = asset
        self.message = message


__all__ = [
    "LanguageReadiness",
    "LanguageReadinessProbeError",
]
