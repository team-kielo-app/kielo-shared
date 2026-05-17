"""Per-request support-locale override prefetch (ADR-008 Phase 5).

Sync `_l10n` callers in the engine (and any other FastAPI service)
can't `await` a per-call DynamicRegistry probe. Restructuring every
deeply-nested helper into `async def` would be a wide blast radius.

Instead this module provides the same override-aware behaviour via a
*per-request prefetch* pattern, modelled on how mature i18n libraries
(django i18n, flask-babel) work:

  1. At request entry, a middleware resolves the request's support
     locale, fires ONE SQL query that fetches every
     `(resource_type='ui.string', language_code=X, status IN ('override','approved'))`
     row for that locale, and stashes the resulting map in a
     `ContextVar` scoped to the request.
  2. The localizer functions (`_l10n` and friends) consult that
     contextvar synchronously before falling through to the in-memory
     seed registry.

Cost: one SQL query per request returning O(N_keys) rows for the
locale. The dict lookup at each `_l10n` call is O(1). The cache is
implicit — a request is the natural cache scope, and admins editing
overrides see the change on the next request.

Source-version validation: each prefetched row carries the
`source_version` it was authored against (sha256 of the English seed
that existed at override-creation time). `_l10n("Practice", lang)`
computes the current source_version from the English text in code; if
the prefetched row's source_version differs, the override is treated
as stale and skipped. This is the same staleness guard the per-call
DynamicRegistry uses, just relocated to the read path.

Wire-up:
    # FastAPI startup
    from kielo_shared.middleware.support_locale_overrides import (
        SupportLocaleOverridesMiddleware,
    )
    app.add_middleware(
        SupportLocaleOverridesMiddleware,
        session_factory=AsyncSessionLocal,
        resolve_locale=resolve_support_locale_from_request,
    )

    # Localizer (e.g. engine ui_strings._l10n)
    from kielo_shared.localization.support_locale_overrides import (
        get_override,
    )

    def _l10n(text: str, lang: str) -> str:
        if override := get_override(text, lang):
            return override
        return _materialized.get(text, {}).get(lang, text)
"""

from __future__ import annotations

import contextvars
import hashlib
import logging
from typing import Optional, Protocol

from kielo_shared.resource_types import UI_STRING

logger = logging.getLogger(__name__)


# Resource type covered by this prefetch path. The contextvar key
# isolates this from other resource types — if a future caller wants
# per-request prefetch for a different resource_type (e.g.
# `notifications.body`), they should use a separate prefetch + context
# rather than mixing namespaces into the same dict.
_OVERRIDES_RESOURCE_TYPE = UI_STRING


# The contextvar stores `(locale, {english_source: (source_version, override_text)})`.
# Locale is captured so the localizer can verify the caller's `lang`
# argument matches what we prefetched for — if they don't match, the
# overrides aren't applicable and the localizer must fall through to
# the seed. Default = ("", {}), which behaves as "no overrides loaded".
_overrides_cv: contextvars.ContextVar[tuple[str, dict[str, tuple[str, str]]]] = (
    contextvars.ContextVar("ui_string_overrides", default=("", {}))
)


class _AsyncSession(Protocol):
    """The subset of SQLAlchemy AsyncSession we need. Declared as a
    Protocol so tests can inject a stub without importing SQLAlchemy."""

    async def execute(self, statement, params=None): ...


class _AsyncSessionFactory(Protocol):
    """An async context manager that yields an _AsyncSession. Matches
    SQLAlchemy `sessionmaker(class_=AsyncSession)` call shape."""

    def __call__(self): ...


_PREFETCH_QUERY = """
    SELECT resource_id, source_version, translated_text
      FROM localization.dynamic_translations
     WHERE resource_type  = :resource_type
       AND language_code  = :language_code
       AND status        IN ('machine', 'override', 'approved')
"""
# IN-clause includes 'machine' so on-demand auto-translated rows
# (written by the autotranslate callback in
# SupportLocaleOverridesMiddleware) become visible on the next request
# WITHOUT requiring admin review. Admin review is still available
# (status='approved'/'override' for explicit accept/edit), but the
# default ladder is: first request returns English + queues auto-
# translate → next request returns auto-translated text → admin can
# tighten via override at any time. Mirrors the user-visible behavior
# of article.title/scenario.title which also serve status='machine'
# rows directly.


async def prefetch_overrides_for_locale(
    session_factory: _AsyncSessionFactory,
    locale: str,
    *,
    resource_type: str = _OVERRIDES_RESOURCE_TYPE,
) -> dict[str, tuple[str, str]]:
    """Fetch all override rows for `(resource_type, locale)`.

    Returns `{resource_id: (source_version, translated_text)}`. The
    `source_version` is preserved so the read-side can validate
    staleness against the current English seed before applying the
    override.

    Locale `en` and the empty string short-circuit to `{}` because
    English is the canonical Tier-A source — there's nothing to
    override.

    DB failures degrade to `{}` (logged) so a localization.dynamic_translations
    outage falls through to seed values rather than crashing requests.
    """
    if not locale or locale == "en":
        return {}

    # Lazy import — sqlalchemy is heavy and not every consumer of this
    # module will have it on PYTHONPATH (the Go side of kielo-shared
    # certainly doesn't, but neither do offline tooling scripts that
    # import the localization helpers).
    try:
        from sqlalchemy import text  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "sqlalchemy not installed; override prefetch is a no-op."
        )
        return {}

    try:
        async with session_factory() as session:
            result = await session.execute(
                text(_PREFETCH_QUERY),
                {"resource_type": resource_type, "language_code": locale},
            )
            rows = result.fetchall()
    except Exception:  # noqa: BLE001 — degrade, never propagate
        logger.exception(
            "Override prefetch failed for locale=%s; falling through to seeds",
            locale,
        )
        return {}

    return {row.resource_id: (row.source_version, row.translated_text) for row in rows}


def set_overrides_for_request(
    locale: str, overrides: dict[str, tuple[str, str]]
) -> contextvars.Token:
    """Bind `(locale, overrides)` to the current request's contextvar.

    Returns the contextvar token so the caller (typically middleware)
    can reset state at request exit. In practice ASGI request scope
    handles isolation between concurrent requests automatically, so
    reset is optional — but explicit token-return keeps the API
    composable for non-middleware callers (background tasks etc.).
    """
    return _overrides_cv.set((locale, overrides))


def clear_overrides(token: Optional[contextvars.Token] = None) -> None:
    """Reset the contextvar. Pass the token returned by
    `set_overrides_for_request` for precise reset, or no arg to clear
    to the empty state."""
    if token is not None:
        _overrides_cv.reset(token)
    else:
        _overrides_cv.set(("", {}))


def get_override(key: str, english_source: str, lang: str) -> Optional[str]:
    """Resolve `(key, lang)` against the request's prefetched overrides.
    Returns the override text if one exists and is current, else `None`
    (caller should fall through to the seed).

    `key` is the registry key (`ui.engine_string.Learn`,
    `ui.email.subject.password_reset`, etc.) — used to look up the
    override row by its `resource_id`.

    `english_source` is the current English seed text. It's used to
    compute the current `source_version` and validate the prefetched
    row hasn't gone stale. Often `english_source == key` (when the
    registry uses english-source-as-key) but they're conceptually
    independent — slug-style keys like `ui.email.subject.password_reset`
    have an English source of "Reset Your Password".

    Validation:
      * `lang` must match the locale the contextvar was prefetched for.
      * The prefetched row's `source_version` must equal sha256 of the
        current `english_source`. A mismatch means the English seed has
        been edited since the override was authored; the override is
        stale and treated as missing.

    Pure sync — no I/O. The cost is two dict lookups + one sha256
    digest (which is itself sub-microsecond for short strings).
    """
    if not lang or lang == "en" or not key or not english_source:
        return None

    locale, overrides = _overrides_cv.get()
    if not overrides or locale != lang:
        return None

    hit = overrides.get(key)
    if hit is None:
        return None

    stored_sv, override_text = hit
    expected_sv = hashlib.sha256(english_source.encode("utf-8")).hexdigest()[:16]
    if stored_sv != expected_sv:
        # Stale override — English source has been edited since the
        # override was authored. Don't apply; fall through to the new
        # English seed (or whatever the localizer's fallback chain
        # returns) until the override is re-authored against the
        # current English.
        return None

    return override_text


# =============================================================================
# Missing-key tracking for on-demand auto-translation (ADR-008 Phase 5.5)
# =============================================================================
#
# When a sync localizer hits a key + locale that has neither a seed
# translation nor a prefetched override, it falls through to the
# English source. To make non-English locales fill in automatically
# (matching the on-demand pattern used by article.title /
# scenario.title), the localizer also calls `register_missing` to
# record the (resource_id, english_source, locale) triple in this
# request-scoped ContextVar.
#
# After the handler returns, the middleware drains the set and fires a
# background autotranslate task (caller-supplied callback) that calls
# the LLM seam for each missing item and writes status='auto' rows to
# `localization.dynamic_translations`. The next request that hits the
# same key+locale finds the row in the prefetch and returns it
# immediately — no English fallback after the first miss.
#
# Why ContextVar rather than a process-global set: a process-global
# would (a) leak state across requests in concurrent FastAPI workers
# and (b) require explicit locking. ContextVar is per-task by ASGI
# convention, so concurrent requests naturally get separate sets.
#
# Dedupe within a request is handled by the `set` type. Cross-request
# dedupe is handled at the seam layer (its single-flight + cache) and
# at the DB layer (`INSERT ... ON CONFLICT DO NOTHING` semantics on
# the unique-by-key constraint).

# (resource_id, english_source, locale) triples.
#
# IMPORTANT: the ContextVar stores a MUTABLE set object — register_missing
# mutates it in place. This is intentional because Starlette's
# BaseHTTPMiddleware spawns the endpoint in a separate anyio task; any
# ContextVar.set() done inside the endpoint task does NOT propagate
# back to the middleware's task scope (that's how contextvar isolation
# works). But the set object the contextvar points to IS shared — both
# tasks see the same set instance because the middleware established
# it at request entry. Mutating in place is the supported way to share
# state across the middleware/endpoint boundary.
_missing_cv: contextvars.ContextVar[set[tuple[str, str, str]]] = (
    contextvars.ContextVar("ui_string_missing", default=set())
)


def init_missing_set_for_request() -> set[tuple[str, str, str]]:
    """Bind a fresh mutable set to the contextvar for this request.
    Called by the middleware at request entry. Returns the bound set
    so the caller can stash a reference if needed.
    """
    fresh: set[tuple[str, str, str]] = set()
    _missing_cv.set(fresh)
    return fresh


def register_missing(resource_id: str, english_source: str, lang: str) -> None:
    """Record that a sync localizer hit (resource_id, lang) with no
    seed and no prefetched override. The middleware drains this set
    post-response and fires the autotranslate callback.

    Skipped silently when:
      * `lang` is empty or `en` (English IS the canonical source;
        nothing to auto-translate).
      * The current contextvar locale doesn't match `lang` (the
        prefetch was scoped to a different locale; firing translate
        for this would create an orphaned row).

    Template-placeholder strings (`text` containing `{`) are also
    skipped — LLM-translating templates without breaking `{}` semantics
    is fragile and only worth ~6 strings; admin manual authoring is
    the right path for those.

    Mutates the set in place — see the _missing_cv definition comment
    for why.
    """
    english_source = (english_source or "").strip()
    resource_id = (resource_id or "").strip()
    if not lang or lang == "en" or not english_source or not resource_id:
        return
    # Skip templates — see docstring.
    if "{" in english_source:
        return
    # Only register for the locale this request's prefetch is scoped
    # to. Cross-locale auto-translate from a single request would be
    # surprising (and the prefetch wouldn't pick up the new row on
    # the next request to a different locale anyway).
    locale, _ = _overrides_cv.get()
    if locale and locale != lang:
        return

    current = _missing_cv.get()
    # If we somehow hit the shared default (caller didn't go through
    # the middleware), promote to a private set so we don't leak across
    # threads.
    if current is _MODULE_DEFAULT_MISSING_SET:
        current = set()
        _missing_cv.set(current)
    current.add((resource_id, english_source, lang))


def consume_missing() -> set[tuple[str, str, str]]:
    """Read the current missing set and reset to empty (in place). Called
    by the middleware after `call_next` returns so the background task
    gets the keys this request hit.

    Mutates in place so the shared set object stays valid; the
    middleware-issued task captures the snapshot returned here.
    """
    current = _missing_cv.get()
    if not current:
        return set()
    snapshot = set(current)
    current.clear()
    return snapshot


# Module-level sentinel used by register_missing to detect the
# uninitialized default. Defined AFTER the helpers because it's
# referenced inside register_missing's lazy-init branch.
_MODULE_DEFAULT_MISSING_SET: set[tuple[str, str, str]] = _missing_cv.get()


__all__ = [
    "prefetch_overrides_for_locale",
    "set_overrides_for_request",
    "clear_overrides",
    "get_override",
    "register_missing",
    "consume_missing",
    "init_missing_set_for_request",
]
