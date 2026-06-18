"""LocalizationProvider Protocol.

Single-method contract: `translate_batch`. A provider may dispatch internally
(true batch prompt, fan-out, hybrid) — the caller only sees ordered results.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from kielo_shared.localization.types import TranslationItem, TranslationResult


@runtime_checkable
class LocalizationProvider(Protocol):
    """Provider contract for localization seams across services.

    Implementations:
      - OpenAIProvider           (this phase)
      - GeminiProvider           (later)
      - OpusMTProvider           (later)
      - InHouseProvider          (later)

    Decorators (also implement Protocol):
      - MetricsDecorator
      - CorrelationDecorator
      - RedisCacheDecorator      (later)
      - CircuitBreakerDecorator  (later)
    """

    @property
    def provider_id(self) -> str:
        """Stable id including a version stamp; used in logs + telemetry."""
        ...

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        """Translate items in order. Result list MUST be the same length.

        Args:
          items: input items to translate.
          source_locale: BCP-47-ish source code ("en", "fi", "sv"). Empty is
            invalid — caller resolves first.
          target_locale: target locale (may be a base like "vi" or BCP-47
            like "vi-VN" — providers normalize internally).
          idempotency_key: optional caller-supplied dedup token; providers
            MAY use it for retry-safety.

        Returns:
          One result per input item, in the same order. On per-item failure
          a provider MAY return the source text passthrough; on whole-batch
          failure it MUST raise.
        """
        ...


__all__ = ["LocalizationProvider"]
