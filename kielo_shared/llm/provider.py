"""LLMProvider Protocol.

Single method: `generate(request) -> result`. Decorators implement the same
Protocol so the stack composes the same way the localization seam does.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from kielo_shared.llm.types import LLMRequest, LLMResult


@runtime_checkable
class LLMProvider(Protocol):
    """Provider contract for LLM calls across services."""

    @property
    def provider_id(self) -> str:
        """Stable id including version stamp; appears in logs + cache keys."""
        ...

    async def generate(self, request: LLMRequest) -> LLMResult:
        """Execute the LLM call and return a single result.

        Implementations MUST:
          * Honor `request.response_schema` when set (populate `parsed`).
          * NOT mutate `request`.
          * Set `provider` on the result.
          * Set `latency_ms` covering the actual provider call.

        Implementations MAY:
          * Raise on hard provider failure (caller / FallbackDecorator
            handles retry).
          * Return `LLMResult(provider="passthrough")` if the request is
            empty / disabled (e.g. dry-run gate).
        """
        ...


__all__ = ["LLMProvider"]
