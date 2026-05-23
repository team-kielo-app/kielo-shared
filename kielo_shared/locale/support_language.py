"""Stateless support-language resolution per ADR-006 §3.83.

Python sibling of ``kielo-shared/middleware/support_language.go``. Every
Kielo service that exposes hydrated localized payloads to clients
previously hand-rolled ``request.query_params.get("support_language_code")``
and stopped there, silently ignoring the ``Accept-Language`` header and
the learning-language fallback that ADR-006 §3.83 mandates:

    explicit query/header → user profile → Accept-Language (BCP47)
                          → fallback to learning language → "en"

This helper consolidates the first, third, and last steps (the
"stateless" subset). The profile-fetch step is a service-specific
concern (only BFF + content-service hydrate profile mid-request) so
callers compose it on top of the result here.

Why FastAPI-shaped vs Starlette-shaped:
  The function takes a ``Request`` typed as the Starlette base so it
  works with both FastAPI handlers and Starlette middleware. The two
  share the same ``query_params`` / ``headers`` API on this surface.
"""

from __future__ import annotations

from typing import Optional

from starlette.requests import Request

from kielo_shared.db_utils import get_active_language
from kielo_shared.locale_constants import (
    LANGUAGE_DISPLAY_NAMES,
    TIER_A_SUPPORT_LOCALE,
    base_locale,
    normalize_accept_language,
    normalize_locale_code,
)

# Canonical query-string parameter for the UI/support language across
# all v3 endpoints. Mirrors Go's ``middleware.SupportLanguageQueryParam``.
SUPPORT_LANGUAGE_QUERY_PARAM = "support_language_code"

# Standard HTTP content-negotiation header. Clients that follow BCP47
# (every mainstream browser, most HTTP libraries, react-native fetch)
# populate it automatically; ignoring it for support-language resolution
# means we serve "en" to a user whose browser explicitly asked for "vi"
# or "fi".
ACCEPT_LANGUAGE_HEADER = "Accept-Language"


def is_supported_support_language(code: Optional[str]) -> bool:
    """Return True when ``code`` is a recognized UI / support-language
    code. Mirrors Go's ``locale.IsSupportedSupportLanguage``: the
    canonical set is the keyset of ``LANGUAGE_DISPLAY_NAMES``. A code
    outside this set has no display name and would surface as a generic
    placeholder in mobile UI — validate at the API boundary so bad
    input gets a 4xx instead of a silent stale-display state.
    """
    normalized = normalize_locale_code(code)
    if not normalized:
        return False
    return normalized in LANGUAGE_DISPLAY_NAMES


def resolve_support_language_stateless(request: Request) -> str:
    """Implement the stateless portion of the ADR-006 §3.83 chain.

    Resolution order (first non-empty supported match wins):

      1. ``?support_language_code=`` query parameter (explicit per-call
         override).
      2. ``Accept-Language`` header (BCP47 — first supported match wins).
      3. Active learning language from the request context (set by the
         engine's ``ActiveLanguageMiddleware``), coerced through the
         support-locale supported set.
      4. ``TIER_A_SUPPORT_LOCALE`` ("en").

    The profile lookup (step 3 in the ADR-006 spec) is omitted because
    it requires an HTTP call back to ``kielo-user-service``, which the
    shared package cannot perform without pulling in service-specific
    dependencies. Callers that need the profile step should compose:

        stateless = resolve_support_language_stateless(request)
        if _is_explicit(request):
            return stateless
        if profile := await fetch_user_profile_locale(user_id):
            return profile
        return stateless

    Returns a non-empty BCP47 base code (e.g. "en", "fi", "vi"). Falls
    through to ``TIER_A_SUPPORT_LOCALE`` rather than returning ``""``
    to keep downstream code free of empty-string branches.
    """
    # 1. Query param.
    raw_query = request.query_params.get(SUPPORT_LANGUAGE_QUERY_PARAM, "")
    if raw_query and raw_query.strip():
        code = base_locale(normalize_accept_language(raw_query))
        if code and is_supported_support_language(code):
            return code

    # 2. Accept-Language header.
    raw_header = request.headers.get(ACCEPT_LANGUAGE_HEADER, "")
    if raw_header and raw_header.strip():
        code = base_locale(normalize_accept_language(raw_header))
        if code and is_supported_support_language(code):
            return code

    # 3. Active learning language (from ActiveLanguageMiddleware contextvar).
    learning = get_active_language()
    if learning:
        code = base_locale(normalize_accept_language(learning))
        if code and is_supported_support_language(code):
            return code

    # 4. Default fallback.
    return TIER_A_SUPPORT_LOCALE


__all__ = [
    "ACCEPT_LANGUAGE_HEADER",
    "SUPPORT_LANGUAGE_QUERY_PARAM",
    "is_supported_support_language",
    "resolve_support_language_stateless",
]
