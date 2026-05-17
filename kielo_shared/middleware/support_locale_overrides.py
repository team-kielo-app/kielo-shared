"""FastAPI middleware that prefetches support-locale overrides per request.

Pairs with `kielo_shared.localization.support_locale_overrides`. At
request entry the middleware:

  1. Resolves the support locale from the request (caller supplies the
     resolver — locale-resolution logic varies by service and is
     already implemented in each endpoint today; the middleware is
     just the glue that runs it once at the boundary).
  2. Fires the prefetch query against `localization.dynamic_translations`.
  3. Stashes the result in the request-scoped `_overrides_cv`
     contextvar so the localizers can pick it up synchronously.

Wire-up (engine, content-service, any FastAPI app):

    from kielo_shared.middleware.support_locale_overrides import (
        SupportLocaleOverridesMiddleware,
    )
    from src.kielolearnengine.db.session import managed_async_session

    def resolve_support_locale(request: Request) -> str:
        # Existing resolver chain: ?support_language_code= →
        # Accept-Language → JWT profile → "en". Each service already
        # has this somewhere; the middleware just calls it.
        return request.headers.get("x-kielo-support-language", "en")

    app.add_middleware(
        SupportLocaleOverridesMiddleware,
        session_factory=managed_async_session,
        resolve_locale=resolve_support_locale,
    )

The middleware is fail-open: any error in the resolver or prefetch
falls through to the seed values (logged at WARNING level). The
request never fails because the override layer fell over.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Iterable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from kielo_shared.localization.support_locale_overrides import (
    clear_overrides,
    consume_missing,
    init_missing_set_for_request,
    prefetch_overrides_for_locale,
    set_overrides_for_request,
)

logger = logging.getLogger(__name__)


LocaleResolver = Callable[[Request], str]
# Callback shape: (missing_items, locale) → awaitable. Each item is
# the (resource_id, english_source, locale) triple recorded by
# `register_missing` during the request. Implementations typically
# call the service's translation seam in a batch and persist
# status='auto' rows to localization.dynamic_translations. Errors
# raised by the callback are caught + logged; they MUST NOT propagate
# (the response has already been sent at this point anyway).
AutoTranslateCallback = Callable[
    [Iterable[tuple[str, str, str]], str], Awaitable[None]
]


class SupportLocaleOverridesMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that prefetches `ui.string` overrides per request
    and (optionally) fires a background autotranslate task for any
    keys that hit a seed-miss during the request.

    The session_factory must produce an async context manager that
    yields a SQLAlchemy AsyncSession. The resolve_locale callable
    extracts the support locale from the incoming request (Accept-
    Language, query param, JWT claim — whatever resolution chain the
    service uses).

    autotranslate_callback is optional. When supplied, the middleware
    drains the missing-key set populated by `register_missing` during
    the request and fires the callback as a detached background task
    AFTER the response is sent. The callback is responsible for
    routing through the service's translation seam and writing
    status='auto' rows to localization.dynamic_translations. Same
    fail-open contract: callback errors are logged, never propagated.
    """

    def __init__(
        self,
        app,
        *,
        session_factory,
        resolve_locale: LocaleResolver,
        autotranslate_callback: Optional[AutoTranslateCallback] = None,
    ) -> None:
        super().__init__(app)
        self._session_factory = session_factory
        self._resolve_locale = resolve_locale
        self._autotranslate_callback = autotranslate_callback

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        token = None
        resolved_locale = ""
        try:
            try:
                resolved_locale = self._resolve_locale(request) or ""
            except Exception:  # noqa: BLE001
                logger.exception(
                    "support-locale resolver raised; skipping override prefetch"
                )
                resolved_locale = ""

            if resolved_locale and resolved_locale != "en":
                overrides = await prefetch_overrides_for_locale(
                    self._session_factory, resolved_locale
                )
                # Set the contextvar even when no overrides exist so
                # `register_missing` knows which locale to scope to.
                # An empty dict is fine — the read path falls through
                # to seed naturally.
                token = set_overrides_for_request(resolved_locale, overrides)
                # Bind a fresh mutable set for missing-key tracking.
                # MUST be done at the middleware layer (not lazily on
                # first register_missing call) because Starlette's
                # BaseHTTPMiddleware runs the endpoint in a separate
                # anyio task — contextvar mutations in the endpoint
                # don't propagate back to the middleware. The endpoint
                # mutates this set object in place; the middleware
                # reads the same instance.
                init_missing_set_for_request()

            response = await call_next(request)
        finally:
            # Drain missing-keys BEFORE clearing the override
            # contextvar — both share the same request scope. Fire the
            # callback as a detached background task (asyncio.create_task
            # rather than await) so the response is already on its way
            # back to the client by the time the LLM seam fires.
            if (
                self._autotranslate_callback is not None
                and resolved_locale
                and resolved_locale != "en"
            ):
                missing = consume_missing()
                if missing:
                    asyncio.create_task(
                        _run_autotranslate(
                            self._autotranslate_callback,
                            missing,
                            resolved_locale,
                        )
                    )

            # Defensive reset. ASGI scope already isolates context per
            # request, so leaking shouldn't happen — but explicit
            # cleanup avoids surprises if the middleware is composed
            # with code that shares scope across requests.
            if token is not None:
                clear_overrides(token)

        return response


async def _run_autotranslate(
    callback: AutoTranslateCallback,
    missing: set[tuple[str, str, str]],
    locale: str,
) -> None:
    """Detached-task wrapper that absorbs all callback errors.
    Background tasks that propagate exceptions to the event loop
    surface as `Task exception was never retrieved` warnings and
    confuse debugging. Catch + log here so the task always terminates
    cleanly."""
    try:
        await callback(missing, locale)
    except Exception:  # noqa: BLE001
        logger.exception(
            "autotranslate callback failed for locale=%s items=%d",
            locale, len(missing),
        )


__all__ = ["SupportLocaleOverridesMiddleware", "AutoTranslateCallback"]
