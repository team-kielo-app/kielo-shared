"""GeminiProvider — Phase C7.

Mirrors `OpenAIProvider`: same batched-JSON contract, same role taxonomy,
same fallback-to-per-item on parse failure. Differences:
  * `provider_id` defaults to `gemini:flash@phase-c`.
  * Wraps `google.genai.Client` (or any callable matching the Gemini text-
    generation surface) injected by the caller — keeps this package free of
    the SDK dep.

Use this as the secondary in `FallbackDecorator(primary=openai, secondary=gemini)`
once both are registered. Switching the primary at runtime is a one-line env
change.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Awaitable, Callable

from kielo_shared.localization.openai_provider import (
    _BATCH_SYSTEM,
    _BATCH_USER,
    _language_name,
    _parse_batch_payload,
    _role_prompt,
    _strip_code_fences,
)
from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# Caller-injected text generator. Signature mirrors the OpenAI provider's
# so the same engine adapter can serve both providers — only the prompt
# routing changes.
GeminiTextGenerator = Callable[
    [str, str, dict | None],
    Awaitable[str | None],
]


class GeminiProvider:
    """Gemini-backed translation provider, batched.

    Args:
      text_generator: async callable that maps `(system_prompt, user_prompt,
        input_variables)` to a string. Engine wires its existing Gemini
        adapter (typically a thin wrapper around `google.genai.Client.aio
        .models.generate_content`).
      provider_id: stable id with version stamp.
      max_batch_items: cap items per call.
      max_parallel_chunks: concurrent chunks under semaphore.
      strict_batch: raise instead of falling back on parse failure (test
        helper).
    """

    def __init__(
        self,
        text_generator: GeminiTextGenerator,
        *,
        provider_id: str = "gemini:flash@phase-c",
        max_batch_items: int = 30,
        max_parallel_chunks: int = 4,
        strict_batch: bool = False,
    ) -> None:
        self._generate = text_generator
        self._provider_id = provider_id
        self._max_batch_items = max_batch_items
        self._max_parallel_chunks = max(1, max_parallel_chunks)
        self._strict_batch = strict_batch

    @property
    def provider_id(self) -> str:
        return self._provider_id

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
        target_base = (target_locale or "").split("-", 1)[0].lower()
        if target_base in {"", "en"}:
            return [_passthrough(item) for item in items]

        chunks: list[list[TranslationItem]] = [
            items[i : i + self._max_batch_items]
            for i in range(0, len(items), self._max_batch_items)
        ]
        if len(chunks) == 1:
            return await self._translate_chunk(
                chunks[0],
                source_locale=source_locale or "en",
                target_locale=target_locale,
            )

        sem = asyncio.Semaphore(self._max_parallel_chunks)

        async def _bounded(chunk):
            async with sem:
                return await self._translate_chunk(
                    chunk,
                    source_locale=source_locale or "en",
                    target_locale=target_locale,
                )

        chunk_results = await asyncio.gather(*(_bounded(c) for c in chunks))
        flat: list[TranslationResult] = []
        for sub in chunk_results:
            flat.extend(sub)
        return flat

    # ──────────────────────────── chunk ──────────────────────────────────

    async def _translate_chunk(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        target_lang = _language_name(target_locale)
        source_lang = _language_name(source_locale)
        sendable_idx: list[int] = [
            i for i, item in enumerate(items) if (item.text or "").strip()
        ]
        if not sendable_idx:
            return [_passthrough(item) for item in items]

        payload = json.dumps(
            [
                {"id": local, "role": items[i].role, "text": items[i].text}
                for local, i in enumerate(sendable_idx)
            ],
            ensure_ascii=False,
        )
        system_prompt = _BATCH_SYSTEM.format(
            source_lang=source_lang, target_lang=target_lang
        )
        started = time.perf_counter()
        raw = await self._generate(system_prompt, _BATCH_USER, {"payload": payload})
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        translations = (
            _parse_batch_payload(raw or "", len(sendable_idx))
            if raw
            else None
        )

        if translations is None:
            if self._strict_batch:
                raise RuntimeError(
                    f"GeminiProvider batch parse failed (strict_batch=True); raw={raw!r}"
                )
            logger.warning(
                "GeminiProvider: batch parse failed, falling back to per-item "
                "(items=%d, target=%s)",
                len(sendable_idx),
                target_locale,
            )
            return await self._translate_per_item(
                items, source_locale=source_locale, target_locale=target_locale
            )

        results: list[TranslationResult] = []
        translated_by_origin = {
            sendable_idx[local]: translations[local]
            for local in range(len(sendable_idx))
        }
        per_item_ms = int(elapsed_ms / max(1, len(sendable_idx)))
        sendable_set = set(sendable_idx)
        for i, item in enumerate(items):
            if i not in sendable_set:
                results.append(_passthrough(item))
                continue
            text = (translated_by_origin.get(i) or "").strip()
            if not text:
                results.append(_passthrough(item))
                continue
            results.append(
                TranslationResult(
                    text=text,
                    provider=self._provider_id,
                    cached=False,
                    latency_ms=per_item_ms,
                    metadata={"role": item.role, "batch_size": len(sendable_idx)},
                )
            )
        return results

    async def _translate_per_item(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        target_lang = _language_name(target_locale)
        results: list[TranslationResult] = []
        for item in items:
            value = (item.text or "").strip()
            if not value:
                results.append(_passthrough(item))
                continue
            prompt = _role_prompt(item.role, target_lang)
            started = time.perf_counter()
            raw = await self._generate(prompt, "{text}", {"text": value})
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            cleaned = _strip_code_fences(raw or "")
            if not cleaned:
                results.append(_passthrough(item))
                continue
            results.append(
                TranslationResult(
                    text=cleaned,
                    provider=f"{self._provider_id}#fallback",
                    cached=False,
                    latency_ms=elapsed_ms,
                    metadata={"role": item.role, "batch_size": 1},
                )
            )
        return results


def _passthrough(item: TranslationItem) -> TranslationResult:
    return TranslationResult(text=item.text, provider="passthrough")


__all__ = ["GeminiProvider", "GeminiTextGenerator"]
