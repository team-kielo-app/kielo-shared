"""Per-request localization budget — Python sibling of Go's
``kielo-shared/localization/budget.go``.

Sweep YYYY: mirrors the TTTT-I budget infrastructure on the Python
side so the engine's localization seam ALSO reports per-request fan-
out costs via the same ``X-Kielo-Loc-*`` response headers. Pre-YYYY
the engine was invisible — only kielo-convo (Go) emitted budget
headers, so dashboards monitoring scenarios couldn't compare
against the engine's roadmap / curriculum / discovery hot paths.

Wire-up:

1. ``LocalizationBudgetMiddleware`` opens a per-request counter on
   the contextvar, runs the handler, reads the snapshot, stamps
   ``X-Kielo-Loc-Refs/Overrides/CacheGets/Providers`` headers.

2. Hot paths call ``record_budget(kind, n)`` at each phase. Today
   the engine's ``content_localizer.localize_batch`` is the
   single seam entry; later sweeps can instrument the structured
   content localizer batch helpers + reusable field localizer to
   distinguish "1 ref via 1 LLM call" from "N refs via 1 LLM call".

3. Background tasks (Pub/Sub workers, cron) don't wire the
   middleware, so ``record_budget`` becomes a no-op for them.
   Same shape as the Go side's behavior under WithBudget-not-set.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class BudgetKind(IntEnum):
    """Categories the localization seam tracks per-request."""

    OVERRIDE_LOOKUP = 0  # override-store DB queries
    CACHE_GET = 1  # Redis GET/MGET round-trips
    PROVIDER_CALL = 2  # LLM / opus-mt provider calls
    REF_RESOLVED = 3  # total refs resolved (a single batch call resolves N refs but issues O(1) RTTs)


@dataclass
class _BudgetCounters:
    """Mutable per-request counters. No atomic needed under CPython's
    GIL for the integer-add pattern; ContextVar isolation handles the
    cross-task case (each asyncio task sees its own ctx)."""

    override_lookups: int = 0
    cache_gets: int = 0
    provider_calls: int = 0
    refs_resolved: int = 0

    def add(self, kind: BudgetKind, n: int) -> None:
        if kind == BudgetKind.OVERRIDE_LOOKUP:
            self.override_lookups += n
        elif kind == BudgetKind.CACHE_GET:
            self.cache_gets += n
        elif kind == BudgetKind.PROVIDER_CALL:
            self.provider_calls += n
        elif kind == BudgetKind.REF_RESOLVED:
            self.refs_resolved += n

    def snapshot(self) -> "BudgetSnapshot":
        return BudgetSnapshot(
            override_lookups=self.override_lookups,
            cache_gets=self.cache_gets,
            provider_calls=self.provider_calls,
            refs_resolved=self.refs_resolved,
        )


@dataclass(frozen=True)
class BudgetSnapshot:
    """Read-side view of the per-request counters.

    Mirrors the Go ``BudgetSnapshot`` struct field-for-field so
    downstream observability code that aggregates across services
    can use the same shape.
    """

    override_lookups: int = 0
    cache_gets: int = 0
    provider_calls: int = 0
    refs_resolved: int = 0


_active_budget: ContextVar[Optional[_BudgetCounters]] = ContextVar(
    "kielo_localization_budget", default=None
)


def with_budget() -> Token:
    """Attach a fresh per-request counter to the current context.

    Mirrors ``WithBudget(ctx)`` in Go. Returns a ContextVar Token the
    caller MUST pass to ``reset_budget`` in a try/finally (or use the
    LocalizationBudgetMiddleware which handles it automatically).

    Idempotent: if a budget is already wired on this ctx, returns a
    Token that resets to the existing value (so calling with_budget
    inside a nested scope doesn't double-stamp).
    """
    existing = _active_budget.get()
    if existing is not None:
        # Already wired — reuse counters; reset will restore current
        # value (which is itself, so it's a no-op token).
        return _active_budget.set(existing)
    return _active_budget.set(_BudgetCounters())


def reset_budget(token: Token) -> None:
    """Restore the budget contextvar to its pre-with_budget state."""
    _active_budget.reset(token)


def budget_from_context() -> Optional[_BudgetCounters]:
    """Return the active counters, or None if no budget is wired."""
    return _active_budget.get()


def budget_snapshot() -> BudgetSnapshot:
    """Return the current snapshot, or a zero snapshot if no budget."""
    counters = _active_budget.get()
    if counters is None:
        return BudgetSnapshot()
    return counters.snapshot()


def record_budget(kind: BudgetKind, n: int = 1) -> None:
    """Increment the counter for ``kind`` by ``n``. No-op when no
    budget is wired (background workers, scripts, unit tests).

    Same shape as Go's ``RecordBudget(ctx, kind, n)``. Called by the
    seam / batch helpers at each phase; external callers shouldn't
    need to.
    """
    counters = _active_budget.get()
    if counters is None:
        return
    counters.add(kind, n)
