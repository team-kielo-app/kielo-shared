"""RoutingDecorator + per-target fast-paths — Phase C4.

The Tier-A passthrough and the Vietnamese fixed-dictionary lookup currently
live duplicated in `structured_content_localizer.py`, `session_support_localizer.py`,
and one or two ingest paths. This module collapses both decisions behind a
single decorator so callers stop re-implementing them:

    OpenAIProvider                       (raw LLM path)
    └─ VietnameseFastPathDecorator       (curated dict bypass; configurable)
       └─ RoutingDecorator               (Tier-A passthrough; gates LLM by target)
          └─ RedisCacheDecorator         (read-through cache)
             └─ CorrelationDecorator     (trace stamping)
                └─ MetricsDecorator      (per-batch metrics)

`VietnameseFastPathDecorator` accepts an injected dict so the engine can pass
its existing curated overrides without exposing engine internals into the
shared package.
"""
from __future__ import annotations

import logging
from typing import Callable

from kielo_shared.localization.provider import LocalizationProvider
from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# Tier A is the source language we always have authoritative copy for.
# English today; the constant lives here so the seam doesn't depend on
# engine-side `locale_constants`.
TIER_A_LOCALE = "en"


def _base(locale: str) -> str:
    return (locale or "").split("-", 1)[0].lower()


# ───────────────────────────── RoutingDecorator ──────────────────────────


class RoutingDecorator:
    """Tier-A passthrough + empty-text passthrough.

    Items whose target locale resolves to Tier A (English today) skip the
    inner provider entirely — the source IS the translation. Same for empty
    items. This is what every caller used to gate inline; centralizing it
    here means a future Tier-A locale change is one constant edit.
    """

    def __init__(self, inner: LocalizationProvider) -> None:
        self._inner = inner

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        if not items:
            return []
        target_base = _base(target_locale)
        if target_base in {"", TIER_A_LOCALE}:
            return [_passthrough(item) for item in items]
        # Drop empty items from the batch but keep their slot in the output
        # so callers don't see a length mismatch.
        sendable_idx: list[int] = [
            i for i, item in enumerate(items) if (item.text or "").strip()
        ]
        if not sendable_idx:
            return [_passthrough(item) for item in items]
        sendable = [items[i] for i in sendable_idx]
        inner_results = await self._inner.translate_batch(
            sendable,
            source_locale=source_locale,
            target_locale=target_locale,
            idempotency_key=idempotency_key,
        )
        if len(inner_results) != len(sendable):
            logger.warning(
                "RoutingDecorator: inner returned %d for %d items; "
                "passthrough-falling back.",
                len(inner_results),
                len(sendable),
            )
            return [_passthrough(item) for item in items]
        out: list[TranslationResult] = []
        merged: dict[int, TranslationResult] = dict(
            zip(sendable_idx, inner_results, strict=True)
        )
        for i, item in enumerate(items):
            out.append(merged.get(i) or _passthrough(item))
        return out


# ─────────────────────── VietnameseFastPathDecorator ─────────────────────


# Type alias for the curated lookup callback the engine injects.
VietnameseLookup = Callable[[str], str | None]


class VietnameseFastPathDecorator:
    """Skip the inner provider when a curated VI translation is on file.

    The engine team maintains a small dictionary of stable, classroom-style
    Vietnamese renderings (e.g. "Quick Practice" → "Luyện tập nhanh"). The
    LLM tends to over-generate for those — burning tokens AND drifting
    away from the intended pedagogy term — so a deterministic dict is
    strictly better when it has a hit.

    The dictionary itself lives in the engine (`_translate_fixed_vi`); the
    decorator takes it as an injected callback so this shared package does
    not depend on engine-side data.
    """

    def __init__(
        self,
        inner: LocalizationProvider,
        lookup: VietnameseLookup,
    ) -> None:
        self._inner = inner
        self._lookup = lookup

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        if not items or _base(target_locale) != "vi":
            return await self._inner.translate_batch(
                items,
                source_locale=source_locale,
                target_locale=target_locale,
                idempotency_key=idempotency_key,
            )

        results: list[TranslationResult | None] = [None] * len(items)
        miss_idx: list[int] = []
        miss_items: list[TranslationItem] = []

        for i, item in enumerate(items):
            value = (item.text or "").strip()
            if not value:
                results[i] = _passthrough(item)
                continue
            override = self._lookup(value)
            if override:
                results[i] = TranslationResult(
                    text=override,
                    provider=f"{self._inner.provider_id}#vi-fixed",
                    cached=True,
                    latency_ms=0,
                    metadata={"role": item.role, "source": "vi_fixed_dict"},
                )
                continue
            miss_idx.append(i)
            miss_items.append(item)

        if miss_items:
            inner_results = await self._inner.translate_batch(
                miss_items,
                source_locale=source_locale,
                target_locale=target_locale,
                idempotency_key=idempotency_key,
            )
            if len(inner_results) != len(miss_items):
                logger.warning(
                    "VietnameseFastPathDecorator: inner returned %d for %d misses",
                    len(inner_results),
                    len(miss_items),
                )
                for slot, item in zip(miss_idx, miss_items, strict=True):
                    results[slot] = _passthrough(item)
            else:
                for slot, r in zip(miss_idx, inner_results, strict=True):
                    results[slot] = r

        return [
            r if r is not None else _passthrough(items[i])
            for i, r in enumerate(results)
        ]


# ──────────────────────────────── helpers ────────────────────────────────


def _passthrough(item: TranslationItem) -> TranslationResult:
    return TranslationResult(text=item.text, provider="passthrough")


__all__ = [
    "RoutingDecorator",
    "TIER_A_LOCALE",
    "VietnameseFastPathDecorator",
    "VietnameseLookup",
]
