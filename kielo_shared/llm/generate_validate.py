"""generate_and_validate — Phase F-lite.

The LLM seam handles "make the call". Around it lives a recurring pattern:

  1. Build the request (already shaped via LLMRequest).
  2. Invoke provider via registry.
  3. If response_schema is set, materialize result.parsed → Pydantic instance.
  4. Run an optional caller-supplied validator (`is this output usable?`).
  5. If parse OR validation fails, retry up to N times.
  6. On success, return the typed instance. On exhaustion, return None.

Today this loop lives copy-pasted across `structured_output`,
`weakness_proactive_remediation_module`, every exercise factory, etc. Each
copy reimplements: model_validate, exception swallow, attempt counter,
log line, observability tag.

F-lite is a small helper that owns the loop. Phase F (full) would compress
prompt-loading + persistence on top, but that's not in scope yet.

Usage:

    request = LLMRequest(
        system_prompt=..., user_prompt=..., variables=...,
        response_schema=MyOutput, task="my_task", cache_policy="none",
    )
    parsed = await generate_and_validate(
        request,
        max_attempts=2,
        validator=lambda inst: inst.score >= 1,
    )
    if parsed is None:
        # exhausted; fall back / 502
        ...
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from kielo_shared.llm.registry import LLMRegistry, get_default_llm_registry
from kielo_shared.llm.types import LLMRequest


logger = logging.getLogger(__name__)


# Caller's optional second-stage validator. Receives the parsed instance
# (Pydantic class OR raw dict / list when no schema is set). Returns True
# to accept, False to discard the attempt and retry. May raise — the
# helper treats raises as a discard.
ResultValidator = Callable[[Any], bool] | Callable[[Any], Awaitable[bool]]


async def generate_and_validate(
    request: LLMRequest,
    *,
    max_attempts: int = 2,
    validator: ResultValidator | None = None,
    registry: LLMRegistry | None = None,
) -> Any | None:
    """Execute an LLM call, parse, optionally validate, retry, return.

    Args:
      request: prepared LLMRequest. `response_schema` set → result is
        rehydrated to that Pydantic class on success.
      max_attempts: total attempts (1 = no retry). Each attempt is a
        full provider round-trip — be conservative.
      validator: optional custom check on the parsed instance. Falsy /
        raised → attempt discarded, next attempt fires.
      registry: dependency-inject a registry for tests; production picks
        the process-global default.

    Returns:
      Validated Pydantic instance (or raw parsed value if no schema).
      None when all attempts produced unparseable / invalid output.
    """
    if max_attempts <= 0:
        return None

    reg = registry or get_default_llm_registry()
    provider = reg.resolve(task=request.task)
    schema = _resolve_schema_class(request.response_schema)
    last_error: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            result = await provider.generate(request)
        except Exception as exc:
            last_error = type(exc).__name__
            logger.warning(
                "generate_and_validate: provider raised on attempt=%d task=%s err=%s",
                attempt,
                request.task,
                last_error,
            )
            continue

        parsed = result.parsed

        # If no schema requested, accept whatever the provider returned.
        if schema is None:
            if validator is not None and not await _run_validator(validator, parsed):
                logger.info(
                    "generate_and_validate: validator rejected attempt=%d task=%s "
                    "(no schema)",
                    attempt,
                    request.task,
                )
                continue
            return parsed

        # Schema requested: ensure we have a typed instance. Cache hits
        # may already rehydrate; live calls return dict (LangChain shape).
        instance: Any | None = None
        if isinstance(parsed, schema):
            instance = parsed
        elif isinstance(parsed, dict):
            instance = _try_materialize(schema, parsed)
        elif parsed is None:
            instance = None
        else:
            # Defensive: provider returned something we don't know how to
            # coerce. Log + retry.
            logger.info(
                "generate_and_validate: unexpected parsed type=%s on attempt=%d "
                "task=%s — discarding.",
                type(parsed).__name__,
                attempt,
                request.task,
            )
            instance = None

        if instance is None:
            last_error = "schema_validate_failed"
            logger.info(
                "generate_and_validate: schema materialize failed attempt=%d task=%s",
                attempt,
                request.task,
            )
            continue

        if validator is not None and not await _run_validator(validator, instance):
            last_error = "validator_rejected"
            logger.info(
                "generate_and_validate: validator rejected attempt=%d task=%s",
                attempt,
                request.task,
            )
            continue

        return instance

    logger.warning(
        "generate_and_validate: exhausted %d attempts task=%s last_error=%s",
        max_attempts,
        request.task,
        last_error,
    )
    return None


# ──────────────────────────── helpers ────────────────────────────────────


def _resolve_schema_class(schema: Any) -> type | None:
    """Same recipe as the cache + provider layers — keep in lockstep so
    `parsed` materialization is consistent across the seam."""
    if schema is None:
        return None
    if isinstance(schema, type):
        return schema
    if isinstance(schema, dict):
        candidate = schema.get("__pydantic__")
        if isinstance(candidate, type):
            return candidate
    return None


def _try_materialize(schema_class: type, payload: dict) -> Any | None:
    """Pydantic v2 `model_validate` with graceful fallback to direct construction.

    Returns None on failure — caller retries or gives up.
    """
    validate = getattr(schema_class, "model_validate", None)
    if callable(validate):
        try:
            return validate(payload)
        except Exception:
            return None
    try:
        return schema_class(**payload)
    except Exception:
        return None


async def _run_validator(validator: ResultValidator, value: Any) -> bool:
    """Run a sync OR async validator and translate raises to False."""
    try:
        outcome = validator(value)
        if hasattr(outcome, "__await__"):
            outcome = await outcome  # type: ignore[assignment]
        return bool(outcome)
    except Exception:
        return False


__all__ = ["ResultValidator", "generate_and_validate"]
