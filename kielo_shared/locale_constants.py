"""Shared locale constants for the Kielo platform.

These constants are the universal answers every service has to use when
localizing content:

  * What language do we *support the learner in* by default? English (TIER_A_SUPPORT_LOCALE).

Missing learning_language_code is not defaulted here. Runtime callers must
provide an explicit authored learning language and fail loud when it is absent.

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

# Languages for which Kielo currently has authored learning content and
# per-language learning schemas. Support/localization locales are broader and
# intentionally continue to include languages such as Vietnamese.
SUPPORTED_LEARNING_LANGUAGES: frozenset[str] = frozenset({"fi", "sv"})

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
    """Normalize input and return it only for authored learning languages."""
    normalized = normalize_locale_code(code)
    return normalized if normalized in SUPPORTED_LEARNING_LANGUAGES else ""


def is_supported_learning_language(code: str | None) -> bool:
    """Return True when ``code`` is an authored learning-content language."""
    return normalize_learning_language_code(code) in SUPPORTED_LEARNING_LANGUAGES


def normalize_supported_learning_language_code(code: str | None) -> str:
    """Explicit alias for learning-language boundaries."""
    return normalize_learning_language_code(code)


def require_supported_learning_language_code(code: str | None) -> str:
    """Resolve a supported learning language, falling back to the active ctx.

    Post-M5 cutover, the schema name (klearn_<lang> / cms_<lang>) is the
    sole source of truth for the active learning language. Per-row /
    per-request ``learning_language_code`` arguments are best-effort hints
    that may be empty when the caller is already running inside an
    ``active_language_scope(...)``. In that case, fall through to the
    contextvar set by middleware / scope helpers rather than raising.

    Callers without the active-language ctx (e.g. CLI tools, batch
    processors) see ``get_active_language()`` return ``None`` and fall
    straight through to the original raise behavior — backwards-compatible
    with every pre-cutover caller.

    Raises ``ValueError`` only when neither the explicit argument nor the
    active-language ctx resolves to a supported value.
    """
    normalized = normalize_supported_learning_language_code(code)
    if normalized:
        return normalized
    # Lazy import to avoid a circular dep with kielo_shared at module init.
    from kielo_shared.db_utils import get_active_language

    fallback = normalize_supported_learning_language_code(get_active_language())
    if fallback:
        return fallback
    raise ValueError("learning_language_code is required and must be one of: fi, sv")


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
    return normalize_locale_code(value)


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

    Returns the canonical base learning-language code when the publisher
    attached a supported value, or ``None`` when the attribute is
    missing/empty/unsupported.

    Subscribers across the platform — both kielolearn-engine and
    kielo-ingest-processor — call this helper so they extract the same
    field, normalize the same way, and reject the same invalid values.
    This is intentionally stricter than support-locale normalization:
    Vietnamese may be a localization language, but it must not become a
    learning schema suffix.
    """
    if attrs is None:
        return None
    raw = attrs.get(LANGUAGE_ATTRIBUTE)
    if not isinstance(raw, str):
        return None
    normalized = normalize_supported_learning_language_code(raw)
    return normalized or None


__all__ = [
    "LANGUAGE_ATTRIBUTE",
    "LANGUAGE_DISPLAY_NAMES",
    "SUPPORTED_LEARNING_LANGUAGES",
    "TIER_A_SUPPORT_LOCALE",
    "base_locale",
    "is_supported_learning_language",
    "language_display_name",
    "language_from_attributes",
    "normalize_accept_language",
    "normalize_learning_language_code",
    "normalize_locale_code",
    "normalize_supported_learning_language_code",
    "normalize_source_locale",
    "require_supported_learning_language_code",
    "support_locale_candidates",
]
