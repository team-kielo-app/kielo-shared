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

import logging
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from kielo_shared.localization.support_locale_overrides import (
    clear_overrides,
    prefetch_overrides_for_locale,
    set_overrides_for_request,
)

logger = logging.getLogger(__name__)


LocaleResolver = Callable[[Request], str]


class SupportLocaleOverridesMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that prefetches `ui.string` overrides per request.

    The session_factory must produce an async context manager that
    yields a SQLAlchemy AsyncSession. The resolve_locale callable
    extracts the support locale from the incoming request (Accept-
    Language, query param, JWT claim — whatever resolution chain the
    service uses).
    """

    def __init__(
        self,
        app,
        *,
        session_factory,
        resolve_locale: LocaleResolver,
    ) -> None:
        super().__init__(app)
        self._session_factory = session_factory
        self._resolve_locale = resolve_locale

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        token = None
        try:
            try:
                locale = self._resolve_locale(request) or ""
            except Exception:  # noqa: BLE001
                logger.exception(
                    "support-locale resolver raised; skipping override prefetch"
                )
                locale = ""

            if locale and locale != "en":
                overrides = await prefetch_overrides_for_locale(
                    self._session_factory, locale
                )
                if overrides:
                    token = set_overrides_for_request(locale, overrides)

            return await call_next(request)
        finally:
            # Defensive reset. ASGI scope already isolates context per
            # request, so leaking shouldn't happen — but explicit
            # cleanup avoids surprises if the middleware is composed
            # with code that shares scope across requests.
            if token is not None:
                clear_overrides(token)


__all__ = ["SupportLocaleOverridesMiddleware"]
