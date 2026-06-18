"""Tests for kielo_shared.pubsub_consumer.process_pull_message.

The helper runs from a Pub/Sub streaming-pull worker thread and bridges
to a target asyncio loop via run_coroutine_threadsafe. These tests
spin up a real event loop on a separate thread for each test so the
threading + ack/nack semantics get exercised end-to-end.
"""
from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import MagicMock

import pytest

from kielo_shared.pubsub_consumer import process_pull_message


def _make_message(data: bytes) -> MagicMock:
    """Build a duck-typed pubsub_v1 Message stand-in.

    The real Message class is C-extension-backed and not constructible
    in tests; we only need the .data attribute + .ack()/.nack() recording
    so MagicMock is sufficient.
    """
    msg = MagicMock()
    msg.data = data
    msg.ack = MagicMock()
    msg.nack = MagicMock()
    msg.attributes = {}
    return msg


def _spin_loop() -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
    """Start a background event loop and return (loop, thread).

    Caller is responsible for stopping the loop via
    `loop.call_soon_threadsafe(loop.stop)` and joining the thread.
    """
    loop = asyncio.new_event_loop()
    started = threading.Event()

    def _run() -> None:
        asyncio.set_event_loop(loop)
        started.set()
        loop.run_forever()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    assert started.wait(timeout=2.0)
    return loop, thread


def _stop_loop(loop: asyncio.AbstractEventLoop, thread: threading.Thread) -> None:
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2.0)
    loop.close()


@pytest.fixture
def background_loop():
    loop, thread = _spin_loop()
    yield loop
    _stop_loop(loop, thread)


@pytest.fixture
def _reset_prom_state():
    """Clear pubsub_ack samples between tests so assertions on
    sample values aren't polluted by prior tests in the file."""
    from kielo_shared.observability import metrics as metrics_mod

    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.PUBSUB_ACK_TOTAL.clear()
    yield
    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.PUBSUB_ACK_TOTAL.clear()


def test_acks_on_handler_success(background_loop, _reset_prom_state):
    msg = _make_message(b'{"k": "v"}')
    seen_payloads: list[dict] = []

    async def _handler(message, payload):
        seen_payloads.append(payload)

    process_pull_message(
        message=msg,
        handler=_handler,
        loop=background_loop,
        service="test-svc",
        topic_label="test_topic",
        handler_timeout=5.0,
    )

    assert seen_payloads == [{"k": "v"}]
    msg.ack.assert_called_once()
    msg.nack.assert_not_called()


def test_nacks_when_handler_raises(background_loop, _reset_prom_state):
    msg = _make_message(b'{"k": "v"}')

    async def _handler(message, payload):
        raise RuntimeError("transient db outage")

    process_pull_message(
        message=msg,
        handler=_handler,
        loop=background_loop,
        service="test-svc",
        topic_label="test_topic",
    )

    msg.nack.assert_called_once()
    msg.ack.assert_not_called()


def test_drops_poison_pill_on_json_parse_error(
    background_loop, _reset_prom_state
):
    msg = _make_message(b"not-valid-json{")
    handler_called = []

    async def _handler(message, payload):
        handler_called.append(True)

    process_pull_message(
        message=msg,
        handler=_handler,
        loop=background_loop,
        service="test-svc",
        topic_label="test_topic",
    )

    assert handler_called == []
    msg.ack.assert_called_once()
    msg.nack.assert_not_called()


def test_nacks_when_loop_unavailable(_reset_prom_state):
    msg = _make_message(b'{"k": "v"}')

    async def _handler(message, payload):
        pytest.fail("handler must not be called when loop is None")

    process_pull_message(
        message=msg,
        handler=_handler,
        loop=None,
        service="test-svc",
        topic_label="test_topic",
    )

    msg.nack.assert_called_once()
    msg.ack.assert_not_called()


def test_nacks_when_handler_times_out(background_loop, _reset_prom_state):
    msg = _make_message(b'{"k": "v"}')

    async def _handler(message, payload):
        # Sleep longer than the test timeout to force a TimeoutError.
        await asyncio.sleep(5.0)

    process_pull_message(
        message=msg,
        handler=_handler,
        loop=background_loop,
        service="test-svc",
        topic_label="test_topic",
        handler_timeout=0.1,
    )

    msg.nack.assert_called_once()
    msg.ack.assert_not_called()


def test_emits_pubsub_ack_counter(background_loop, _reset_prom_state):
    """Verify the helper feeds the kielo_pubsub_ack_total counter
    so worker-pull listeners get the same telemetry as the push
    middleware path."""
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import PUBSUB_ACK_TOTAL

    msg_ok = _make_message(b'{"k": "v"}')
    msg_err = _make_message(b'{"k": "v"}')
    msg_drop = _make_message(b"bad-json")

    async def _ok(message, payload):
        return

    async def _bad(message, payload):
        raise RuntimeError("boom")

    process_pull_message(
        message=msg_ok,
        handler=_ok,
        loop=background_loop,
        service="test-svc",
        topic_label="t1",
    )
    process_pull_message(
        message=msg_err,
        handler=_bad,
        loop=background_loop,
        service="test-svc",
        topic_label="t1",
    )
    process_pull_message(
        message=msg_drop,
        handler=_ok,
        loop=background_loop,
        service="test-svc",
        topic_label="t1",
    )

    ack_sample = PUBSUB_ACK_TOTAL.labels(
        service="test-svc", topic="t1", outcome="ack"
    )
    nack_sample = PUBSUB_ACK_TOTAL.labels(
        service="test-svc", topic="t1", outcome="nack"
    )
    drop_sample = PUBSUB_ACK_TOTAL.labels(
        service="test-svc", topic="t1", outcome="drop"
    )
    assert ack_sample._value.get() == 1
    assert nack_sample._value.get() == 1
    assert drop_sample._value.get() == 1


def test_handler_completes_synchronously_in_callback_thread(
    background_loop, _reset_prom_state
):
    """The callback MUST block until the handler returns — otherwise
    ack/nack would race with the handler's actual outcome. This is the
    bug F3 fixes vs the prior call_soon_threadsafe + create_task pattern."""
    msg = _make_message(b'{"k": "v"}')
    handler_started = threading.Event()
    handler_finished = threading.Event()

    async def _handler(message, payload):
        handler_started.set()
        # Small delay so we can observe ack-after-finish via
        # event ordering vs ack assertions.
        await asyncio.sleep(0.05)
        handler_finished.set()

    # Run on this thread (caller plays the role of the pubsub
    # streaming-pull callback thread).
    t0 = time.monotonic()
    process_pull_message(
        message=msg,
        handler=_handler,
        loop=background_loop,
        service="test-svc",
        topic_label="t1",
    )
    elapsed = time.monotonic() - t0

    assert handler_started.is_set()
    assert handler_finished.is_set()
    # Should have waited at least the sleep duration.
    assert elapsed >= 0.04
    msg.ack.assert_called_once()
