"""Helpers for spawning background `asyncio.Task`s with safe error handling.

Without these helpers, the common pattern across the codebase is:

    asyncio.create_task(_some_async_helper())

That works in steady state, but any exception raised inside
`_some_async_helper` disappears into asyncio's default
"Task exception was never retrieved" handler — a single log line at
WARNING level that nobody alerts on.

`spawn_background_task(coro, name=..., service=...)` wraps the create
with `add_done_callback` so:

  * exception → log at WARNING + emit
    `kielo_side_effect_failed_total{service, kind=f"background_task.{name}"}`
  * cancellation → log at DEBUG (cancellations are usually intentional
    shutdown; the caller decides whether to filter further)
  * success → no log (would be too noisy on hot paths)

Returns the task so the caller can still .cancel() / await it if they
want — same API as `asyncio.create_task`.

Use this from any code that spawns a side-effect-only coroutine the
caller doesn't intend to await:

    spawn_background_task(
        _record_cache_warmup(item_id),
        name="cache_warmup",
        service="kielolearn-engine",
    )
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Coroutine, Optional


logger = logging.getLogger(__name__)

# In-flight background tasks (strong refs; see spawn_background_task).
_BACKGROUND_TASKS: set = set()


def spawn_background_task(
    coro: Coroutine[Any, Any, Any],
    *,
    name: str,
    service: str,
) -> asyncio.Task:
    """Schedule `coro` as a background task with done-callback wiring.

    `name` is the side-effect tag (e.g. "concept_hub_warmup",
    "tts_cache_write") and feeds into the
    `kielo_side_effect_failed_total{kind="background_task.<name>"}`
    metric label. Keep it stable per call site; the label is bounded
    by the number of background-task spawn locations.

    `service` is the short service name pinned per process
    ("kielolearn-engine", "kielo-cms", ...). Matches the same label
    used by the other observability emitters.
    """
    task = asyncio.create_task(coro)

    def _on_done(t: asyncio.Task) -> None:
        # Local import to avoid a module-load cycle: metrics.py
        # depends on prometheus_client (optional), and this module
        # is imported widely.
        from kielo_shared.observability.metrics import side_effect_failed_emit

        try:
            exc = t.exception()
        except asyncio.CancelledError:
            logger.debug(
                "spawn_background_task: task cancelled service=%s name=%s",
                service,
                name,
            )
            return
        if exc is not None:
            logger.warning(
                "spawn_background_task: task raised service=%s name=%s err=%s",
                service,
                name,
                exc,
                exc_info=(type(exc), exc, exc.__traceback__),
            )
            side_effect_failed_emit(
                service=service,
                kind=f"background_task.{name}",
                exc=exc,
            )

    task.add_done_callback(_on_done)
    # Strong reference until completion: the event loop keeps only weak
    # refs to tasks, so a background task whose returned handle the caller
    # discards (the common fire-and-forget pattern this helper exists for)
    # can be garbage-collected mid-run and silently vanish. Discard runs
    # after _on_done, so the set stays bounded to in-flight tasks.
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return task


def spawn_background_task_lazy(
    coro_factory,
    *,
    name: str,
    service: str,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> "Optional[asyncio.Task]":
    """Like `spawn_background_task` but builds the coroutine inside
    a scheduled callback so it can be invoked from a non-async
    callback (e.g. a Pub/Sub streaming-pull thread).

    `loop` is the target event loop. If None, attempts the running
    loop; returns None if no loop is available (caller decides
    whether that's fatal).
    """
    try:
        target_loop = loop or asyncio.get_running_loop()
    except RuntimeError:
        # No running loop in this thread.
        logger.warning(
            "spawn_background_task_lazy: no running loop service=%s name=%s",
            service,
            name,
        )
        return None

    coro = coro_factory()
    if target_loop.is_running():
        # We're already on the target loop's thread — `run_coroutine_threadsafe`
        # would deadlock. Schedule directly.
        return spawn_background_task(coro, name=name, service=service)

    # Cross-thread schedule.
    future = asyncio.run_coroutine_threadsafe(coro, target_loop)

    def _on_done(f) -> None:
        from kielo_shared.observability.metrics import side_effect_failed_emit

        try:
            exc = f.exception()
        except Exception:
            return
        if exc is not None:
            logger.warning(
                "spawn_background_task_lazy: task raised service=%s name=%s err=%s",
                service,
                name,
                exc,
                exc_info=(type(exc), exc, exc.__traceback__),
            )
            side_effect_failed_emit(
                service=service,
                kind=f"background_task.{name}",
                exc=exc,
            )

    future.add_done_callback(_on_done)
    # `concurrent.futures.Future` isn't an asyncio.Task; callers that
    # need to .cancel() should use spawn_background_task directly.
    return None


__all__ = [
    "spawn_background_task",
    "spawn_background_task_lazy",
]
