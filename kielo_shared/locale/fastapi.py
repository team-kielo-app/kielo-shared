"""FastAPI dependency wrappers around the locale resolver.

Thin glue between FastAPI's ``Depends(...)`` mechanism and the
framework-neutral resolver in
``kielo_shared.locale.support_language``. Lives in its own module so
services that don't use FastAPI (workers, CLI tools, raw scripts)
don't pay the FastAPI import cost just by reaching for
``kielo_shared.locale``.

Usage in a FastAPI handler:

    from kielo_shared.locale.fastapi import get_support_language

    @router.get("/roadmap/lessons")
    async def list_roadmap_lessons(
        user_id: uuid.UUID = Query(...),
        support_language_code: str = Depends(get_support_language),
        ...
    ):
        ...

The dependency takes a ``Request`` (FastAPI injects this automatically
for any positional parameter typed as ``Request``) and runs the
ADR-006 §3.83 resolution chain. See
``resolve_support_language_stateless`` for the full chain.

Trade-off vs declaring ``support_language_code: str = Query(...)``
directly on each handler: the query parameter no longer appears in
the OpenAPI schema as a top-level documented field. The resolver
still HONORS an explicit ``?support_language_code=`` value (it reads
``request.query_params`` first), so the wire contract is unchanged
for callers that already know about the param. Clients generated
from OpenAPI may need to set the value via headers or by passing the
raw query string. If full OpenAPI surface coverage becomes required,
swap this dependency for a variant that re-declares the Query
parameter (kept commented out at the bottom of this file as a
documented escape hatch).
"""

from __future__ import annotations

from starlette.requests import Request

from .support_language import resolve_support_language_stateless


def get_support_language(request: Request) -> str:
    """FastAPI dependency that resolves the support language.

    Drop-in replacement for handlers that previously read
    ``support_language_code: str = Query("")``. Honors the same
    ADR-006 §3.83 chain documented on
    ``resolve_support_language_stateless``:

      1. ``?support_language_code=`` query parameter
      2. ``Accept-Language`` header (BCP47)
      3. Active learning-language contextvar
      4. ``TIER_A_SUPPORT_LOCALE`` ("en")

    Returns a non-empty BCP47 base code (never ``""``).
    """
    return resolve_support_language_stateless(request)


__all__ = ["get_support_language"]
