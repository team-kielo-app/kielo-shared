"""Sweep YYYY: Starlette middleware that stamps per-request
localization budget headers on every response.

Python sibling of the Go ``kielo-shared/middleware/localization_budget.go``
LocalizationBudget Echo middleware + LocalizationBudgetStdlib chi
variant. Reads counters populated by the seam (and the engine's
batch helpers) via ``record_budget``; emits the same
``X-Kielo-Loc-Refs / Overrides / CacheGets / Providers`` header
quartet so observability dashboards aggregate across language
boundaries (Go services + Python engine) without per-service
shape divergence.

Wire-up:

    from kielo_shared.middleware.localization_budget import (
        LocalizationBudgetMiddleware,
    )

    app = FastAPI()
    app.add_middleware(LocalizationBudgetMiddleware)

Place AFTER any auth / language middlewares — the counters are
opened on every request including unauth'd 401 responses (a
malicious client triggering N seam calls before failing auth still
shows up in the metrics).
"""

from __future__ import annotations

from typing import Awaitable, Callable

from kielo_shared.localization.budget import (
    budget_snapshot,
    reset_budget,
    with_budget,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


HEADER_REFS = "X-Kielo-Loc-Refs"
HEADER_OVERRIDES = "X-Kielo-Loc-Overrides"
HEADER_CACHE_GETS = "X-Kielo-Loc-CacheGets"
HEADER_PROVIDERS = "X-Kielo-Loc-Providers"


class LocalizationBudgetMiddleware(BaseHTTPMiddleware):
    """Per-request localization budget headers."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        token = with_budget()
        try:
            response = await call_next(request)
        finally:
            snapshot = budget_snapshot()
            reset_budget(token)
        # Stamp headers AFTER restoring the contextvar so the snapshot
        # reflects the just-completed handler's work, not any cleanup
        # that may run post-response.
        response.headers[HEADER_REFS] = str(snapshot.refs_resolved)
        response.headers[HEADER_OVERRIDES] = str(snapshot.override_lookups)
        response.headers[HEADER_CACHE_GETS] = str(snapshot.cache_gets)
        response.headers[HEADER_PROVIDERS] = str(snapshot.provider_calls)
        return response
