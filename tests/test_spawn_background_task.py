"""Tests for kielo_shared.observability.spawn_background_task.

The wrapper around `asyncio.create_task` exists so background side-
effect coroutines don't disappear into asyncio's default
"Task exception was never retrieved" handler. These tests verify:

  * exceptions in the spawned coro emit the side_effect counter
  * cancellations don't emit (intentional shutdown path)
  * successful completion is silent (no log spam on hot paths)
  * the task is returned so callers can still .cancel() / await it
"""
from __future__ import annotations

import asyncio

import pytest

from kielo_shared.observability import spawn_background_task


@pytest.fixture
def _reset_counter():
    from kielo_shared.observability import metrics as metrics_mod

    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.SIDE_EFFECT_FAILED_TOTAL.clear()
    yield
    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.SIDE_EFFECT_FAILED_TOTAL.clear()


@pytest.mark.asyncio
async def test_emits_on_exception(_reset_counter):
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import SIDE_EFFECT_FAILED_TOTAL

    async def _bad():
        raise RuntimeError("simulated background failure")

    task = spawn_background_task(_bad(), name="unit_test", service="test-svc")
    # Wait for the done-callback to fire.
    try:
        await task
    except RuntimeError:
        pass
    # Yield once so the done-callback finishes.
    await asyncio.sleep(0)

    sample = SIDE_EFFECT_FAILED_TOTAL.labels(
        service="test-svc", kind="background_task.unit_test"
    )
    assert sample._value.get() == 1


@pytest.mark.asyncio
async def test_no_emit_on_success(_reset_counter):
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import SIDE_EFFECT_FAILED_TOTAL

    async def _ok():
        return "fine"

    task = spawn_background_task(_ok(), name="unit_test_ok", service="test-svc")
    await task
    await asyncio.sleep(0)

    samples = list(SIDE_EFFECT_FAILED_TOTAL.collect()[0].samples)
    assert not any(
        s.labels.get("kind") == "background_task.unit_test_ok" and s.value > 0
        for s in samples
    )


@pytest.mark.asyncio
async def test_no_emit_on_cancellation(_reset_counter):
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import SIDE_EFFECT_FAILED_TOTAL

    async def _slow():
        await asyncio.sleep(10)

    task = spawn_background_task(_slow(), name="unit_test_cancel", service="test-svc")
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await asyncio.sleep(0)

    samples = list(SIDE_EFFECT_FAILED_TOTAL.collect()[0].samples)
    assert not any(
        s.labels.get("kind") == "background_task.unit_test_cancel" and s.value > 0
        for s in samples
    )


@pytest.mark.asyncio
async def test_returns_cancellable_task(_reset_counter):
    """The returned object is an asyncio.Task so callers can still
    .cancel() it on shutdown."""
    async def _slow():
        await asyncio.sleep(10)

    task = spawn_background_task(_slow(), name="unit_test_return", service="test-svc")
    assert isinstance(task, asyncio.Task)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
