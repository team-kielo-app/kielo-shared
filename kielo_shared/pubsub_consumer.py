"""Pub/Sub consumer helpers — pull-subscription side of the Pub/Sub seam.

The Google client library's pull subscription delivers messages on a
worker thread via ``SubscriberClient.subscribe(callback=...)``. The
callback is sync, so async handlers have to bridge the boundary via
``asyncio.run_coroutine_threadsafe`` (or worse: ``call_soon_threadsafe``
+ fire-and-forget ``create_task``). The fire-and-forget pattern is a
silent-event-loss footgun:

* if the callback returns before the coroutine finishes, the message
  is held by the streaming client until ``ack()``/``nack()`` is called
  inside the coroutine — fine in steady state, but
* if the coroutine raises and the ``except`` branch acks "to avoid
  poison loops", a transient DB or HTTP error becomes a permanent
  drop — Pub/Sub never redelivers, the event is gone.

This helper centralises the correct recipe:

* Run the async handler synchronously to completion via
  ``run_coroutine_threadsafe(...).result(timeout=...)`` so the
  callback thread blocks until the handler finishes.
* Ack on success.
* Nack on transient exception so Pub/Sub redelivers per its
  retry/deadletter policy — the right place to decide "this is
  unrecoverable" is the subscription's dead-letter config, not the
  handler.
* Ack on json parse errors (poison pill — redelivery won't help).
* Always emit ``kielo_pubsub_ack_total`` via
  ``kielo_shared.observability.pubsub_ack_emit`` so worker-pull
  listeners get the same telemetry the push-middleware path provides.

Use from a streaming-pull callback:

    def _callback(message):
        process_pull_message(
            message=message,
            handler=self._process_message,
            loop=self._loop,
            service="kielolearn-engine",
            topic_label="word_enrichment",
            handler_timeout=300.0,
        )
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
from typing import Any, Awaitable, Callable, Coroutine, Optional, TYPE_CHECKING, cast

if TYPE_CHECKING:
    # google.cloud.pubsub_v1 has a hefty import; only typed-import it.
    # Used in PullHandler / process_pull_message string annotations
    # below — vulture is told via tool.vulture.ignore_names that
    # `Message` is legitimately referenced via forward refs.
    from google.cloud.pubsub_v1.subscriber.message import Message
else:
    Message = Any  # runtime type-erasure; the helper works on duck-typed messages


logger = logging.getLogger(__name__)


# Sentinel timeout: handlers that don't pass one default to 5 minutes,
# matching the Pub/Sub default ack-deadline upper bound (600s) with
# headroom for the streaming client's lease extension to renew. Callers
# with shorter SLAs (real-time view recording) should pass a smaller value.
DEFAULT_HANDLER_TIMEOUT_SECONDS = 300.0


PullHandler = Callable[["Message", dict[str, Any]], Awaitable[None]]


def process_pull_message(
    *,
    message: "Message",
    handler: PullHandler,
    loop: Optional[asyncio.AbstractEventLoop],
    service: str,
    topic_label: str,
    handler_timeout: float = DEFAULT_HANDLER_TIMEOUT_SECONDS,
) -> None:
    """Run ``handler(message, payload)`` synchronously to completion from
    a Pub/Sub streaming-pull callback, then ack/nack based on outcome.

    Behaviour:

    * Parses ``message.data`` as JSON. On JSONDecodeError, logs at
      WARNING, acks (poison pill — redelivery won't fix it), and
      emits ``outcome="drop"``.
    * If ``loop`` is None or closed, nacks (transient — service may
      not be fully initialised), emits ``outcome="nack"``.
    * Schedules ``handler(message, payload)`` on ``loop`` via
      ``run_coroutine_threadsafe`` and blocks the callback thread on
      ``.result(timeout=handler_timeout)``. On success, acks and
      emits ``outcome="ack"``.
    * On TimeoutError, logs at ERROR, nacks (transient — redeliver
      after backoff), emits ``outcome="nack"``.
    * On any other exception, logs at ERROR, nacks, emits
      ``outcome="nack"``. The DLQ subscription (configured on the
      Pub/Sub side, not in code) handles repeated nacks for the
      same message.

    The handler MUST itself catch domain-specific exceptions it can
    recover from inline (e.g. malformed-payload validation that's
    distinct from transport-layer failures). Any exception that
    surfaces from the coroutine becomes a nack — design accordingly.
    """
    from kielo_shared.observability import pubsub_ack_emit

    try:
        payload = json.loads(message.data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning(
            "pubsub_consumer: dropping unparseable message service=%s topic=%s err=%s",
            service,
            topic_label,
            exc,
        )
        try:
            message.ack()
        except Exception as ack_exc:
            logger.debug("pubsub_consumer: ack-after-parse-error failed: %s", ack_exc)
        pubsub_ack_emit(service=service, topic=topic_label, outcome="drop")
        return

    if loop is None or loop.is_closed():
        logger.error(
            "pubsub_consumer: event loop unavailable service=%s topic=%s",
            service,
            topic_label,
        )
        try:
            message.nack()
        except Exception as nack_exc:
            logger.debug("pubsub_consumer: nack-without-loop failed: %s", nack_exc)
        pubsub_ack_emit(service=service, topic=topic_label, outcome="nack")
        return

    # mypy: PullHandler returns Awaitable[None] which is structurally
    # a Coroutine in practice (async def). Cast to satisfy
    # run_coroutine_threadsafe's stricter Coroutine bound. Future is
    # typed explicitly so callers don't get Any.
    coro = cast("Coroutine[Any, Any, None]", handler(message, payload))
    future: concurrent.futures.Future[None] = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        future.result(timeout=handler_timeout)
    except asyncio.TimeoutError:
        # Cancel the in-flight coroutine so it doesn't keep running
        # past the ack deadline; Pub/Sub will redeliver to a fresh
        # subscriber that races against the leftover work.
        future.cancel()
        logger.error(
            "pubsub_consumer: handler timed out service=%s topic=%s timeout_s=%.1f",
            service,
            topic_label,
            handler_timeout,
        )
        try:
            message.nack()
        except Exception as nack_exc:
            logger.debug("pubsub_consumer: nack-after-timeout failed: %s", nack_exc)
        pubsub_ack_emit(service=service, topic=topic_label, outcome="nack")
        return
    except Exception as exc:
        logger.error(
            "pubsub_consumer: handler raised service=%s topic=%s err=%s",
            service,
            topic_label,
            exc,
            exc_info=True,
        )
        try:
            message.nack()
        except Exception as nack_exc:
            logger.debug("pubsub_consumer: nack-after-error failed: %s", nack_exc)
        pubsub_ack_emit(service=service, topic=topic_label, outcome="nack")
        return

    try:
        message.ack()
    except Exception as ack_exc:
        logger.debug("pubsub_consumer: ack-after-success failed: %s", ack_exc)
    pubsub_ack_emit(service=service, topic=topic_label, outcome="ack")


__all__ = [
    "DEFAULT_HANDLER_TIMEOUT_SECONDS",
    "PullHandler",
    "process_pull_message",
]
