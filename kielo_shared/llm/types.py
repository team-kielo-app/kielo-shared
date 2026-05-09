"""LLM request/response value types.

`LLMRequest` is the single shape every LLM call goes through. The fields:

  * `system_prompt` / `user_prompt` / `variables`: plain LangChain-style
    template inputs. Engine `llm_service.generate_text` already accepts
    this shape.
  * `response_schema`: optional Pydantic / dict schema. When set, the
    provider routes to a JSON-output model and `LLMResult.parsed` is
    populated.
  * `task`: free-form caller tag ("grammar_example", "topic_naming",
    "evaluation"). Drives metrics + cache namespacing.
  * `prompt_version`: bumped by the caller when a prompt changes
    materially. Becomes part of the cache key so a prompt change
    auto-invalidates without manual cache flush.
  * `cache_policy`: opt-in. Only "read_write" results in cache use; the
    default "none" never reads or writes the cache. This prevents
    personalized / session / evaluation calls from being silently
    cross-contaminated.
  * `cache_key`: optional explicit dedup key. When None, the provider
    derives one from `task + prompt_version + sha256(prompts + variables)`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


# Phase D ships only "none" + "read_write". Future expansion candidates:
# "read_only" (force-fresh on miss without writing), "write_only"
# (rebuild without serving stale).
CachePolicy = Literal["none", "read_write"]


@dataclass(frozen=True)
class LLMRequest:
    """Single LLM invocation.

    Frozen so passing the same request to multiple decorators / providers
    can never mutate it. Re-use is safe; mutate-and-resend is forbidden.
    """

    system_prompt: str
    user_prompt: str
    variables: dict[str, Any] = field(default_factory=dict)
    response_schema: dict[str, Any] | None = None
    task: str = "generic"
    prompt_version: str = "v1"
    cache_policy: CachePolicy = "none"
    cache_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMResult:
    """LLM response.

    `text` is always the raw string the model produced (post code-fence
    stripping, post per-provider sanitation). `parsed` is non-None only
    when `response_schema` was supplied and parsing succeeded.

    Provenance fields mirror `kielo_shared.localization.TranslationResult`
    so logs from the two seams correlate cleanly.
    """

    text: str
    parsed: Any | None = None
    provider: str = "passthrough"
    cached: bool = False
    latency_ms: int = 0
    correlation_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


__all__ = ["CachePolicy", "LLMRequest", "LLMResult"]
