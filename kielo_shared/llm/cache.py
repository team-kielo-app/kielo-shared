"""LLMCacheDecorator — opt-in via cache_policy.

Default cache_policy is "none". The decorator MUST NOT cache or read
unless the caller has explicitly set policy="read_write". This is the
critical scope correction over the localization-cache decorator: general
LLM calls are not always deterministic.

Cache key recipe:
    llm:{provider_id}:{task}:{prompt_version}:{key}

Where `key` is `request.cache_key` if set, else
`sha256(system_prompt|user_prompt|stable_json(variables)|response_schema_str)[:32]`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Protocol

from kielo_shared.llm.provider import LLMProvider
from kielo_shared.llm.types import LLMRequest, LLMResult


logger = logging.getLogger(__name__)


class RedisAsyncClient(Protocol):
    async def get(self, key: str) -> Any: ...

    async def set(self, key: str, value: str, ex: int | None = None) -> Any: ...


def _stable_json(value: Any) -> str:
    """JSON-encode with sorted keys + minimal separators so the same dict
    always serializes byte-for-byte identical."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return repr(value)


def _derive_cache_key(request: LLMRequest) -> str:
    # Phase D+2.1: ALWAYS sha256 the key, even when the caller provided
    # an explicit `cache_key`. Reasons:
    #   * Bounded Redis key length (some explicit keys today carry full
    #     prompts / glosses → unbounded growth).
    #   * Privacy: raw user content stops leaking into Redis SCAN /
    #     ops dashboards via the key namespace.
    #   * Parity with the Go mirror's `CacheKey` recipe.
    if request.cache_key:
        return hashlib.sha256(request.cache_key.encode("utf-8")).hexdigest()[:32]
    parts = [
        request.system_prompt,
        request.user_prompt,
        _stable_json(request.variables),
        _stable_json(request.response_schema),
    ]
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()[:32]


class LLMCacheDecorator:
    """Read-through cache. Fully bypassed when cache_policy != 'read_write'.

    The cached value stores `text` and the JSON-serialized `parsed` payload
    (when the original result had one). `provider` / `latency_ms` /
    `correlation_id` are recomputed for the current request — never served
    stale.
    """

    def __init__(
        self,
        inner: LLMProvider,
        redis: RedisAsyncClient | None,
        *,
        ttl_sec: int = 7 * 24 * 3600,
        key_prefix: str | None = None,
    ) -> None:
        self._inner = inner
        self._redis = redis
        self._ttl = ttl_sec
        self._prefix = key_prefix

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def generate(self, request: LLMRequest) -> LLMResult:
        # OPT-IN gate: cache only when caller asked. The default is "none"
        # so personalized / session-state-bearing prompts pass through to
        # the inner provider unaltered.
        if request.cache_policy != "read_write" or self._redis is None:
            return await self._inner.generate(request)

        key = self._maybe_prefix(self._build_key(request))
        cached = await self._safe_get(key)
        if cached is not None:
            try:
                payload = json.loads(cached)
            except (TypeError, ValueError):
                payload = None
            if isinstance(payload, dict) and isinstance(payload.get("text"), str):
                # Schemaful callers (Phase D+1) ship Pydantic classes via
                # `request.response_schema`. On cache hit the stored `parsed`
                # is JSON-friendly (dict / list / scalar). Rehydrate to a
                # Pydantic instance so schemaful callers keep typed access
                # without re-checking `isinstance(parsed, dict)`. Failure
                # falls through to the dict so the cache layer never makes
                # a hit worse than a miss.
                parsed_payload = payload.get("parsed")
                rehydrated = _maybe_rehydrate_parsed(
                    request.response_schema, parsed_payload
                )
                return LLMResult(
                    text=payload["text"],
                    parsed=rehydrated,
                    provider=self._inner.provider_id,
                    cached=True,
                    latency_ms=0,
                    correlation_id="",
                    metadata={"cache": "hit", "task": request.task},
                )

        result = await self._inner.generate(request)
        if (result.text or "").strip() and result.provider != "passthrough":
            await self._safe_set(
                key,
                json.dumps(
                    {"text": result.text, "parsed": _serialize_parsed(result.parsed)}
                ),
            )
        return result

    # ──────────────────────────── helpers ────────────────────────────────

    def _build_key(self, request: LLMRequest) -> str:
        derived = _derive_cache_key(request)
        return f"llm:{self._inner.provider_id}:{request.task}:{request.prompt_version}:{derived}"

    def _maybe_prefix(self, key: str) -> str:
        return f"{self._prefix}:{key}" if self._prefix else key

    async def _safe_get(self, key: str) -> str | None:
        try:
            value = await self._redis.get(key)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("LLMCacheDecorator GET failed key=%s: %s", key, exc)
            return None
        if value is None:
            return None
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if isinstance(value, str):
            return value
        return None

    async def _safe_set(self, key: str, payload: str) -> None:
        try:
            await self._redis.set(key, payload, ex=self._ttl)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("LLMCacheDecorator SET failed key=%s: %s", key, exc)


def _maybe_rehydrate_parsed(schema: Any, payload: Any) -> Any:
    """Rebuild a Pydantic instance from a JSON-friendly cache payload.

    Returns the original payload (dict / list / scalar / None) when:
      * `schema` isn't a class we can instantiate.
      * `payload` is already None / not a dict.
      * Pydantic validation fails.

    The cache layer must never make a hit worse than a miss — falling
    back to the raw dict keeps the result consumable.
    """
    if payload is None:
        return None
    schema_class = _resolve_schema_class(schema)
    if schema_class is None:
        return payload
    if not isinstance(payload, dict):
        return payload
    # Pydantic v2: model_validate. Fall back to direct instantiation
    # when the class is plain (non-Pydantic) so non-Pydantic schemas
    # still degrade gracefully.
    validate = getattr(schema_class, "model_validate", None)
    if callable(validate):
        try:
            return validate(payload)
        except Exception:
            return payload
    try:
        return schema_class(**payload)
    except Exception:
        return payload


def _resolve_schema_class(schema: Any) -> type | None:
    """Mirror of `openai_provider._resolve_schema_class` so the cache layer
    doesn't import a sibling module just for one helper."""
    if schema is None:
        return None
    if isinstance(schema, type):
        return schema
    if isinstance(schema, dict):
        candidate = schema.get("__pydantic__")
        if isinstance(candidate, type):
            return candidate
    return None


def _serialize_parsed(parsed: Any) -> Any:
    """Best-effort make `parsed` JSON-friendly for cache write."""
    if parsed is None:
        return None
    if isinstance(parsed, (str, int, float, bool, list, dict)):
        return parsed
    # Pydantic BaseModel — duck-type rather than import.
    dump = getattr(parsed, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json")
        except Exception:
            return None
    return None


__all__ = ["LLMCacheDecorator", "RedisAsyncClient"]
