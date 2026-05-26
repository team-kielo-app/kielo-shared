"""sync_bridge — Phase D+3 scaffolding.

Lets sync callers (ingest pipeline steps that run in a thread pool, CLI
maintenance tools) hit the async LLM seam without restructuring the call
stack. Two helpers:

  * `run_sync(coro)`: drive any single coroutine to completion. Picks the
    right strategy based on whether a loop is currently running on this
    thread:
      - No running loop → `asyncio.run(coro)` (creates + tears down a loop).
      - Running loop on a different thread → use it via
        `asyncio.run_coroutine_threadsafe` and block on `Future.result`.
      - Running loop on THIS thread → caller bug. We refuse with a
        clear error rather than swallow it; mixing sync and async on the
        same loop deadlocks.

  * `call_llm_sync(request)`: shorthand that routes an `LLMRequest`
    through the engine's registry and returns the JSON-shaped dict (or
    `None`). Mirrors the engine's `call_llm_json` API surface.

Phase D+3 will migrate one ingest call site (recommended: the
`grammar_quality.review_grammar_concepts_with_llm` per-concept review
loop — deterministic per concept_id, safe to cache `read_write`) using
this bridge.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Awaitable, TypeVar

from kielo_shared.llm.registry import LLMRegistry, get_default_llm_registry
from kielo_shared.llm.types import LLMRequest


logger = logging.getLogger(__name__)


T = TypeVar("T")


def run_sync(coro: Awaitable[T]) -> T:
    """Drive a coroutine to completion from sync code.

    Strategy by current loop state:
      * No loop on this thread → `asyncio.run`.
      * Running loop on another thread → `run_coroutine_threadsafe`.
      * Running loop on this thread → raises (deadlock-prone).
    """
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None

    if running is None:
        return asyncio.run(coro)  # type: ignore[arg-type]

    # If we're on the same OS thread as the running loop, scheduling on
    # it would deadlock — wait waits for the loop to advance, but the
    # loop is parked here. Refuse loud.
    if running._thread_id == threading.get_ident():  # type: ignore[attr-defined]
        raise RuntimeError(
            "run_sync was called from inside the same event loop thread. "
            "Use `await` directly instead of run_sync, or move the sync "
            "caller to a thread (e.g. asyncio.to_thread)."
        )

    fut = asyncio.run_coroutine_threadsafe(_as_coro(coro), running)
    return fut.result()


async def _as_coro(value: Awaitable[T]) -> T:
    """Wrap a generic Awaitable in a real coroutine for run_coroutine_threadsafe."""
    return await value


def call_llm_sync(
    request: LLMRequest,
    *,
    registry: LLMRegistry | None = None,
) -> dict | None:
    """Sync wrapper around the registry. Returns dict (or None).

    Same caller-shape contract as the engine's `call_llm_json` so a future
    ingest migration plugs in cleanly. Pydantic instances are dumped to
    dict at the boundary — sync callers historically index via .get()/[].

    Note: callers MUST be on a worker thread (or a CLI process), not
    inside an async route. See `run_sync` constraints.
    """
    return run_sync(_call_async(request, registry))


def call_llm_text_sync(
    request: LLMRequest,
    *,
    registry: LLMRegistry | None = None,
) -> str:
    """Sync wrapper for text-only LLM calls — returns the raw response string.

    Use this from ingest pipeline steps that historically called
    `generate_content_traced(prompt, ...) -> str`. The seam plumbs the
    same telemetry + caching but the caller-facing return shape stays
    `str` so legacy parse code doesn't need to change.

    Returns the empty string when the provider produced nothing (rather
    than None) so callers can pass straight into `parse_*_response(text)`.
    """
    return run_sync(_call_text_async(request, registry))


async def _call_text_async(request: LLMRequest, registry: LLMRegistry | None) -> str:
    reg = registry or get_default_llm_registry()
    provider = reg.resolve(task=request.task)
    result = await provider.generate(request)
    return result.text or ""


async def _call_async(request: LLMRequest, registry: LLMRegistry | None) -> dict | None:
    reg = registry or get_default_llm_registry()
    provider = reg.resolve(task=request.task)
    result = await provider.generate(request)
    parsed = result.parsed
    if parsed is None or isinstance(parsed, dict):
        return parsed
    dump = getattr(parsed, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:
            return None
    return None


__all__ = ["call_llm_sync", "call_llm_text_sync", "run_sync"]
