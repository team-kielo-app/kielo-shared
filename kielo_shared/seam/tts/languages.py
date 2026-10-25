"""Canonical Kielo language -> BCP-47 tag map for Gemini TTS.

Mirrors `seam/tts/gemini/languages.go`; both are tested against
`seam/tts/gemini/testdata/language_tags.json`.
"""

from __future__ import annotations

LANGUAGE_CODES: dict[str, str] = {
    "fi": "fi-FI",
    "sv": "sv-SE",
    "en": "en-US",
    "et": "et-EE",
    "de": "de-DE",
    "fr": "fr-FR",
    "es": "es-ES",
    "vi": "vi-VN",
    "zh": "cmn-CN",
}


def language_tag(language: str) -> str:
    """A bare code maps through LANGUAGE_CODES; a tag with a region passes through
    (underscores become hyphens); an unknown bare code is returned unchanged."""
    base = (language or "").strip().replace("_", "-")
    if "-" in base:
        return base
    return LANGUAGE_CODES.get(base.lower(), base)
