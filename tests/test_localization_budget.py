"""Sweep YYYY: unit tests for the Python localization budget
infrastructure + the LocalizationBudgetMiddleware Starlette wrapper.

Mirrors the Go-side TTTT-I regression tests in
``kielo-shared/middleware/localization_budget_test.go``.
"""

from __future__ import annotations

import asyncio
import pytest

from kielo_shared.localization.budget import (
    BudgetKind,
    BudgetSnapshot,
    budget_from_context,
    budget_snapshot,
    record_budget,
    reset_budget,
    with_budget,
)


# ============================================================================
# Direct budget helpers
# ============================================================================


def test_record_budget_noop_when_no_budget_wired():
    """Without ``with_budget`` open, ``record_budget`` is a no-op
    (background workers, scripts, unit tests get this behavior).
    """
    # Sanity: contextvar isolation should leave the counter unset at
    # test entry (pytest gives each test a fresh ctx in default mode).
    assert budget_from_context() is None
    record_budget(BudgetKind.REF_RESOLVED, 5)
    record_budget(BudgetKind.PROVIDER_CALL, 1)
    # Still no counter — no-op.
    assert budget_from_context() is None
    # Snapshot returns zero shape.
    snap = budget_snapshot()
    assert snap == BudgetSnapshot()


def test_with_budget_isolates_counters_per_scope():
    token = with_budget()
    try:
        record_budget(BudgetKind.REF_RESOLVED, 3)
        record_budget(BudgetKind.OVERRIDE_LOOKUP, 1)
        record_budget(BudgetKind.CACHE_GET, 2)
        record_budget(BudgetKind.PROVIDER_CALL, 1)
        snap = budget_snapshot()
        assert snap.refs_resolved == 3
        assert snap.override_lookups == 1
        assert snap.cache_gets == 2
        assert snap.provider_calls == 1
    finally:
        reset_budget(token)
    # Post-reset: scope closed, no counter visible.
    assert budget_from_context() is None


def test_nested_with_budget_reuses_existing_counters():
    """Nested ``with_budget`` calls accumulate into the SAME counters;
    they don't reset to zero. Matches Go's WithBudget guard.
    """
    outer = with_budget()
    try:
        record_budget(BudgetKind.REF_RESOLVED, 2)
        inner = with_budget()
        try:
            record_budget(BudgetKind.REF_RESOLVED, 3)
            # Inner sees the cumulative count.
            assert budget_snapshot().refs_resolved == 5
        finally:
            reset_budget(inner)
        # Outer still sees the cumulative count post-inner-close.
        assert budget_snapshot().refs_resolved == 5
    finally:
        reset_budget(outer)


@pytest.mark.asyncio
async def test_contextvar_isolation_across_asyncio_tasks():
    """Each asyncio task gets its own contextvar; concurrent tasks
    don't pollute each other's budget counters.
    """

    async def worker(n_refs: int) -> BudgetSnapshot:
        token = with_budget()
        try:
            record_budget(BudgetKind.REF_RESOLVED, n_refs)
            # Yield so the scheduler can interleave us with siblings.
            await asyncio.sleep(0)
            return budget_snapshot()
        finally:
            reset_budget(token)

    results = await asyncio.gather(worker(1), worker(5), worker(10))
    assert [r.refs_resolved for r in results] == [1, 5, 10]


# ============================================================================
# Starlette middleware
# ============================================================================


@pytest.mark.asyncio
async def test_middleware_stamps_response_headers():
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from kielo_shared.middleware.localization_budget import (
        HEADER_CACHE_GETS,
        HEADER_OVERRIDES,
        HEADER_PROVIDERS,
        HEADER_REFS,
        LocalizationBudgetMiddleware,
    )

    async def hello(request):
        # Simulate the seam recording work.
        record_budget(BudgetKind.REF_RESOLVED, 22)
        record_budget(BudgetKind.OVERRIDE_LOOKUP, 1)
        record_budget(BudgetKind.CACHE_GET, 1)
        record_budget(BudgetKind.PROVIDER_CALL, 1)
        return PlainTextResponse("hello")

    app = Starlette(routes=[Route("/", hello)])
    app.add_middleware(LocalizationBudgetMiddleware)
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    # Mirrors the TTTT-I live trace: `Refs:22 Overrides:1 CacheGets:1
    # Providers:1` (pre-TTTT-B Overrides would have been 22).
    assert resp.headers[HEADER_REFS] == "22"
    assert resp.headers[HEADER_OVERRIDES] == "1"
    assert resp.headers[HEADER_CACHE_GETS] == "1"
    assert resp.headers[HEADER_PROVIDERS] == "1"


@pytest.mark.asyncio
async def test_middleware_zero_when_handler_does_not_record():
    """Handler doesn't touch the seam → headers show zero. Important:
    the headers are always present (not omitted) so observability
    dashboards can distinguish "0 work" from "header missing".
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from kielo_shared.middleware.localization_budget import (
        HEADER_CACHE_GETS,
        HEADER_OVERRIDES,
        HEADER_PROVIDERS,
        HEADER_REFS,
        LocalizationBudgetMiddleware,
    )

    async def hello(request):
        return PlainTextResponse("hello")

    app = Starlette(routes=[Route("/", hello)])
    app.add_middleware(LocalizationBudgetMiddleware)
    client = TestClient(app)
    resp = client.get("/")
    assert resp.headers[HEADER_REFS] == "0"
    assert resp.headers[HEADER_OVERRIDES] == "0"
    assert resp.headers[HEADER_CACHE_GETS] == "0"
    assert resp.headers[HEADER_PROVIDERS] == "0"


@pytest.mark.asyncio
async def test_middleware_isolates_concurrent_requests():
    """Two concurrent requests through the same app see their own
    counters — no cross-pollination from contextvar leaks.
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from kielo_shared.middleware.localization_budget import (
        HEADER_REFS,
        LocalizationBudgetMiddleware,
    )

    async def hello(request):
        n = int(request.query_params.get("n", "0"))
        record_budget(BudgetKind.REF_RESOLVED, n)
        # Yield to the scheduler — without contextvar isolation, the
        # interleaved sibling request would pollute this counter.
        await asyncio.sleep(0)
        return PlainTextResponse(str(n))

    app = Starlette(routes=[Route("/", hello)])
    app.add_middleware(LocalizationBudgetMiddleware)
    client = TestClient(app)

    # Sequential calls (TestClient is sync) — proves the contextvar
    # is reset between requests AT MINIMUM. asyncio.gather isolation
    # is exercised in test_contextvar_isolation_across_asyncio_tasks.
    r1 = client.get("/?n=7")
    r2 = client.get("/?n=3")
    assert r1.headers[HEADER_REFS] == "7"
    assert r2.headers[HEADER_REFS] == "3"
