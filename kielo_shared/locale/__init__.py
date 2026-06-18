"""kielo_shared.locale — locale resolution helpers.

Python siblings to the Go ``kielo-shared/locale`` and
``kielo-shared/middleware/support_language.go`` helpers. Each function
mirrors the wire-shape decisions of the Go side so a request crossing
the Go/Python boundary resolves to the same locale.

Currently exposes:

  * ``resolve_support_language_stateless`` — Pythonic port of Go's
    ``ResolveSupportLanguageStateless``. Implements the stateless
    portion of the ADR-006 §3.83 resolution chain for the
    ``support_language_code`` (UI / translation locale).
  * ``is_supported_support_language`` — predicate matching Go's
    ``IsSupportedSupportLanguage``.

The constants (``TIER_A_SUPPORT_LOCALE``, ``LANGUAGE_DISPLAY_NAMES``,
etc.) live in ``kielo_shared.locale_constants`` because they were the
first locale primitives the platform shipped; this package re-exports
the support-language subset for code that doesn't care about the
historical split.
"""

from __future__ import annotations

from .support_language import (
    SUPPORT_LANGUAGE_QUERY_PARAM,
    ACCEPT_LANGUAGE_HEADER,
    is_supported_support_language,
    resolve_support_language_stateless,
)

__all__ = [
    "ACCEPT_LANGUAGE_HEADER",
    "SUPPORT_LANGUAGE_QUERY_PARAM",
    "is_supported_support_language",
    "resolve_support_language_stateless",
]
