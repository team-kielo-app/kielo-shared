"""The trace (a contextvar) must reach a coroutine that a sync thread hands to another thread's loop.

`asyncio.run_coroutine_threadsafe` does this on its own: `call_soon_threadsafe` copies the caller's context when
it is called, and the task made inside that callback copies it again. These tests pin that behaviour for the
two bridges that rely on it, so a change to either bridge (a custom executor, a `context=` argument) cannot
silently drop the trace from log lines.
"""
from __future__ import annotations

import asyncio
import threading

import pytest

from kielo_shared.llm.sync_bridge import run_sync
from kielo_shared.observability import spawn_background_task_lazy
from kielo_shared.trace import (
    current_trace_context,
    new_trace_context,
    reset_current_trace_context,
    set_current_trace_context,
)


@pytest.fixture
def loop_thread():
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)
    loop.close()


def test_run_sync_carries_the_callers_trace_into_the_loop_thread(loop_thread):
    tc = new_trace_context()
    seen: list[str] = []

    async def read_trace() -> str:
        trace_id = current_trace_context().trace_id
        seen.append(trace_id)
        return trace_id

    async def drive() -> str:
        return await asyncio.to_thread(_call_run_sync_with_trace, tc, read_trace)

    got = asyncio.run_coroutine_threadsafe(drive(), loop_thread).result(5)
    assert got == tc.trace_id == seen[0]


def _call_run_sync_with_trace(tc, factory) -> str:
    token = set_current_trace_context(tc)
    try:
        return run_sync(factory())
    finally:
        reset_current_trace_context(token)


def test_run_sync_from_a_worker_thread_targets_the_running_loop(loop_thread):
    tc = new_trace_context()
    result: dict[str, str] = {}

    async def read_trace() -> str:
        return current_trace_context().trace_id

    def worker() -> None:
        token = set_current_trace_context(tc)
        try:
            running = loop_thread
            fut = asyncio.run_coroutine_threadsafe(read_trace(), running)
            result["trace_id"] = fut.result(5)
        finally:
            reset_current_trace_context(token)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(5)
    assert result["trace_id"] == tc.trace_id


def test_spawn_background_task_lazy_from_a_callback_thread_keeps_the_trace(loop_thread):
    tc = new_trace_context()
    seen: list[str] = []
    done = threading.Event()

    async def read_trace() -> None:
        seen.append(current_trace_context().trace_id)
        done.set()

    def callback_thread() -> None:
        token = set_current_trace_context(tc)
        try:
            spawn_background_task_lazy(read_trace, name="t", service="svc", loop=loop_thread)
        finally:
            reset_current_trace_context(token)

    thread = threading.Thread(target=callback_thread)
    thread.start()
    thread.join(5)
    assert done.wait(5)
    assert seen == [tc.trace_id]
