"""Shared locale constants for the Kielo platform.

These two constants are the universal answers to two questions every
service has to answer when localizing content:

  * What language do we *teach* by default? Finnish (LEGACY_DEFAULT_LEARNING_LANGUAGE).
  * What language do we *support the learner in* by default? English (TIER_A_SUPPORT_LOCALE).

Pre-rollout publishers may emit messages without a learning_language_code
attribute and pre-rollout DB rows may have NULL learning_language_code.
These constants are the single source of truth for what those legacy
gaps resolve to.

Kept in kielo_shared so every Python service (kielolearn-engine,
kielo-ingest-processor, future Python services) imports the same value
rather than redefining it locally.
"""

from __future__ import annotations

from typing import Mapping, Optional

# Canonical Pub/Sub message attribute name used to propagate the active
# learning language from publishers to consumers across all Kielo
# services. Mirrors `pubsubutil.LanguageAttribute` in the Go side and
# the X-Kielo-Learning-Language HTTP header.
LANGUAGE_ATTRIBUTE: str = "learning_language_code"

# The default learning language for legacy data where learning_language_code
# is NULL or missing. Finnish is the original/default learning language of
# the platform; the schema-per-language migration preserves this.
LEGACY_DEFAULT_LEARNING_LANGUAGE: str = "fi"

# The Tier-A support language. English is the universal fallback for
# hints, glosses, explanations, and other localized support content.
TIER_A_SUPPORT_LOCALE: str = "en"

# Canonical mapping from base language code to its English display name.
# Used by:
#   * LLM prompts that need to name the learner's language ("You are a
#     {language} dictionary assistant...")
#   * Admin UI labels
#   * Telemetry / log fields
#
# Single source of truth so a service can't accidentally drop to a
# generic placeholder ("learning-language") when handling a locale that
# the platform officially supports. Add new locales here, not in a
# per-feature map. Keys are normalized base codes (matching
# normalize_locale_code output); values are the canonical English names.
LANGUAGE_DISPLAY_NAMES: Mapping[str, str] = {
    "ar": "Arabic",
    "bn": "Bengali",
    "de": "German",
    "en": "English",
    "es": "Spanish",
    "fi": "Finnish",
    "fr": "French",
    "hi": "Hindi",
    "hu": "Hungarian",
    "it": "Italian",
    "ja": "Japanese",
    "ko": "Korean",
    "nl": "Dutch",
    "pl": "Polish",
    "pt": "Portuguese",
    "ru": "Russian",
    "sr": "Serbian",
    "sv": "Swedish",
    "th": "Thai",
    "tr": "Turkish",
    "uk": "Ukrainian",
    "vi": "Vietnamese",
    "zh": "Chinese",
}


def language_display_name(code: str | None, fallback: str = "") -> str:
    """Return the English display name for a base locale code.

    Normalizes input first, so callers can pass any locale-like value
    (``"vi"``, ``"vi-VN"``, ``"vn"`` for the Vietnamese alias). Falls
    back to ``fallback`` (or the normalized code itself if no fallback
    is supplied) when the code isn't in the canonical map — never returns
    an empty string for non-empty input.
    """
    normalized = normalize_locale_code(code)
    if not normalized:
        return fallback
    return LANGUAGE_DISPLAY_NAMES.get(normalized, fallback or normalized)


def normalize_locale_code(code: str | None) -> str:
    """Normalize locale-like input to the platform's base language code."""
    if not isinstance(code, str):
        return ""
    code = code.replace("_", "-").strip()
    if not code:
        return ""

    base = code.split("-", 1)[0].strip().lower()
    return "vi" if base == "vn" else base


def normalize_learning_language_code(code: str | None) -> str:
    """Normalize locale-like input and return only the base learning language."""
    return normalize_locale_code(code)


def normalize_source_locale(code: str | None) -> str:
    """Normalize authored/source locale to the platform's base language code."""
    return normalize_locale_code(code)


def normalize_accept_language(value: str | None) -> str:
    """Normalize either a plain locale or an Accept-Language header value."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value:
        return ""
    first = value.split(",", 1)[0].split(";", 1)[0]
    return normalize_locale_code(first)


def base_locale(value: str | None) -> str:
    """Return the normalized base locale for locale-like input."""
    return normalize_learning_language_code(value)


def support_locale_candidates(requested: str | None) -> list[str]:
    """Return base support-language lookup candidates plus English fallback."""
    normalized = normalize_locale_code(requested)
    if not normalized:
        return []

    out: list[str] = []

    def append_unique(value: str | None) -> None:
        candidate = normalize_locale_code(value)
        if candidate and candidate not in out:
            out.append(candidate)

    append_unique(normalized)
    if normalized != TIER_A_SUPPORT_LOCALE:
        append_unique(TIER_A_SUPPORT_LOCALE)
    return out


def language_from_attributes(
    attrs: Optional[Mapping[str, str]],
) -> Optional[str]:
    """Extract a normalized learning_language_code from Pub/Sub attributes.

    Returns the canonical base language code (``"sv"``, ``"vi"``, ...)
    when the publisher attached a recognizable value, or ``None`` when
    the attribute is missing/empty/unparseable.

    Subscribers across the platform — both kielolearn-engine and
    kielo-ingest-processor — call this helper so they extract the same
    field, normalize the same way, and reject the same invalid values.
    Validation happens at the schema-routing layer (db_utils) rather
    than here; this function's job is normalization, not regex enforcement.
    """
    if attrs is None:
        return None
    raw = attrs.get(LANGUAGE_ATTRIBUTE)
    if not isinstance(raw, str):
        return None
    normalized = normalize_learning_language_code(raw)
    return normalized or None


__all__ = [
    "LANGUAGE_ATTRIBUTE",
    "LANGUAGE_DISPLAY_NAMES",
    "LEGACY_DEFAULT_LEARNING_LANGUAGE",
    "TIER_A_SUPPORT_LOCALE",
    "base_locale",
    "language_display_name",
    "language_from_attributes",
    "normalize_accept_language",
    "normalize_learning_language_code",
    "normalize_locale_code",
    "normalize_source_locale",
    "support_locale_candidates",
]
