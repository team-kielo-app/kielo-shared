"""OpenAIProvider — batched LLM translation.

Phase B contract:
  - PRIMARY path: ONE LLM call for the whole batch using a structured JSON
    request. The model receives N items, returns N items in the same order.
  - FALLBACK path: per-item calls (current `localize_llm_*` behavior). Used
    when batch JSON fails to parse, length mismatches, or the model returns
    a malformed payload.

The provider does not import LangChain / OpenAI SDK directly — it accepts
two injected callables (`text_generator` and `single_text_generator`) so:
  - kielo-shared keeps its lean deps (no Langchain pull-in)
  - tests can inject deterministic stubs
  - swapping to a different SDK happens at the wire site, not here
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Awaitable, Callable

from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# Function signature matching kielolearn-engine's `llm_service.generate_text`.
# (system_prompt, user_prompt, input_variables) -> Optional[str].
TextGenerator = Callable[
    [str, str, dict | None],
    Awaitable[str | None],
]


_LANGUAGE_NAMES = {
    "en": "English",
    "fi": "Finnish",
    "sv": "Swedish",
    "vi": "Vietnamese",
    "de": "German",
    "es": "Spanish",
    "fr": "French",
    "no": "Norwegian",
    "da": "Danish",
}


def _language_name(code: str) -> str:
    base = (code or "").split("-", 1)[0].lower().strip()
    return _LANGUAGE_NAMES.get(base, base or "the target language")


# ────────────────────── per-role prompt templates ────────────────────────

# Sweep UU (2026-05-30): the preservation-rule sentences used to
# hardcode "Finnish" — baked-in assumption that the only learning
# language was Finnish. Now that sv (and forward, other languages)
# are supported, the rule generalises to "preserve any embedded
# non-English (learning-language) tokens / inflections / grammar
# markers exactly". The seam doesn't know which learning language
# the embedded tokens belong to (the same English support string
# can be served to fi and sv learners), so the prompt has to be
# language-agnostic at this layer.

_PLAIN_PROMPT = (
    "Translate English educational content into natural {lang} for "
    "language learners. Preserve any embedded non-English tokens "
    "(learning-language words, inflected forms, quoted examples, "
    "and grammar markers like case suffixes) exactly as written. "
    "Do not add commentary."
)

_HTML_PROMPT = (
    "Translate the visible English text inside the provided HTML into "
    "natural {lang} for language learners. Preserve all HTML tags and "
    "attributes exactly. Preserve any embedded non-English tokens "
    "(learning-language words, inflected forms, and grammar markers) "
    "exactly as written."
)

_GLOSS_PROMPT = (
    "Translate short English glossary text into natural {lang}. Output "
    "only the target language ({lang}). Do not output any other language. "
    "Preserve slashes, semicolons, and commas when they separate senses."
)


def _role_prompt(role: str, lang: str) -> str:
    if role == "html":
        return _HTML_PROMPT.format(lang=lang)
    if role == "gloss":
        return _GLOSS_PROMPT.format(lang=lang)
    return _PLAIN_PROMPT.format(lang=lang)


_BATCH_SYSTEM = (
    "You are a translation engine for a language-learning platform. "
    "You will receive a JSON array of items to translate from {source_lang} "
    "to {target_lang}. Each item has an 'id', a 'role' (plain | gloss | "
    "html), and 'text'. Apply the role-specific translation rules:\n"
    "- plain: natural prose; preserve any embedded non-{source_lang} "
    "tokens (learning-language words, inflected forms, quoted examples, "
    "grammar markers like case suffixes) exactly. No commentary.\n"
    "- gloss: short glossary; output ONLY {target_lang}. Do not output "
    "{source_lang} or any other language. Preserve slashes, semicolons, "
    "and commas that separate senses.\n"
    "- html: preserve every HTML tag and attribute exactly; translate "
    "only the visible text. Output must remain valid HTML.\n"
    "Return ONLY a JSON array of objects with 'id' and 'text' keys, in the "
    "same order as the input. No markdown, no commentary, no prose outside "
    "the JSON."
)

_BATCH_USER = "{payload}"


# ───────────────────────── helpers ───────────────────────────────────────


def _strip_code_fences(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return text.strip()


def _parse_batch_payload(raw: str, expected: int) -> list[str] | None:
    """Parse the JSON array the model returns. Returns ordered text list,
    or None if parsing/shape verification fails — caller falls back."""
    cleaned = _strip_code_fences(raw)
    if not cleaned:
        return None
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or len(parsed) != expected:
        return None
    by_id: dict[int, str] = {}
    for entry in parsed:
        if not isinstance(entry, dict):
            return None
        try:
            idx = int(entry.get("id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        text = entry.get("text")
        if not isinstance(text, str):
            return None
        by_id[idx] = text
    if set(by_id.keys()) != set(range(expected)):
        return None
    return [by_id[i] for i in range(expected)]


# ────────────────────────────── provider ─────────────────────────────────


class OpenAIProvider:
    """Batched OpenAI-backed translation provider.

    Args:
      text_generator: async callable matching engine `llm_service.generate_text`
        signature. Engine wires its existing service in; tests inject a stub.
      provider_id: stable id including version (logs / telemetry).
      max_batch_items: cap items per LLM call; provider auto-chunks larger
        batches into multiple sequential calls. Stays well below context
        limits even for verbose role prompts.
      strict_batch: if True, raise on batch-parse failure instead of
        falling back to per-item. Tests use this to assert the batch path
        actually fires.
    """

    def __init__(
        self,
        text_generator: TextGenerator,
        *,
        provider_id: str = "openai:gpt-4o-mini@phase-b",
        max_batch_items: int = 30,
        max_parallel_chunks: int = 4,
        strict_batch: bool = False,
    ) -> None:
        self._generate = text_generator
        self._provider_id = provider_id
        self._max_batch_items = max_batch_items
        # Phase C2: when an input exceeds max_batch_items, fan out chunks
        # in parallel under this bound. 4 was picked to stay safely under
        # OpenAI's per-key rate limits while still cutting wall-clock
        # roughly proportional to chunk count.
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

        # Honor a Tier-A target ("en" today) by passthrough — saves provider
        # round-trips when callers haven't gated upstream.
        target_base = (target_locale or "").split("-", 1)[0].lower()
        if target_base in {"", "en"}:
            return [self._passthrough(item) for item in items]

        # Slice into chunks that fit one LLM call. Phase C2: chunks now run
        # in parallel under a semaphore — for a 27-item session that fits
        # in one chunk this is identical to before, but a 100-item ingest
        # batch goes from ~5 sequential calls to ~5/4 wall-time units.
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

        async def _bounded(chunk: list[TranslationItem]) -> list[TranslationResult]:
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

    # ─────────────────────────── internals ───────────────────────────────

    def _passthrough(self, item: TranslationItem) -> TranslationResult:
        return TranslationResult(
            text=item.text,
            provider="passthrough",
            cached=False,
            latency_ms=0,
        )

    async def _translate_chunk(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        target_lang = _language_name(target_locale)
        source_lang = _language_name(source_locale)

        # Skip empties before sending to the LLM — saves tokens and keeps
        # idx<->item alignment trivial.
        sendable_indices: list[int] = [
            i for i, item in enumerate(items) if (item.text or "").strip()
        ]
        if not sendable_indices:
            return [self._passthrough(item) for item in items]

        payload = json.dumps(
            [
                {
                    "id": local_id,
                    "role": items[i].role,
                    "text": items[i].text,
                }
                for local_id, i in enumerate(sendable_indices)
            ],
            ensure_ascii=False,
        )

        system_prompt = _BATCH_SYSTEM.format(
            source_lang=source_lang, target_lang=target_lang
        )
        started = time.perf_counter()
        raw = await self._generate(
            system_prompt,
            _BATCH_USER,
            {"payload": payload},
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        translations = (
            _parse_batch_payload(raw or "", len(sendable_indices)) if raw else None
        )

        if translations is None:
            if self._strict_batch:
                raise RuntimeError(
                    f"OpenAIProvider batch parse failed (strict_batch=True); raw={raw!r}"
                )
            logger.warning(
                "OpenAIProvider: batch parse failed, falling back to per-item "
                "(items=%d, target=%s)",
                len(sendable_indices),
                target_locale,
            )
            return await self._translate_per_item(
                items,
                source_locale=source_locale,
                target_locale=target_locale,
            )

        # Build results, slot translated values into sendable indices and
        # passthrough the empties.
        results: list[TranslationResult] = []
        sendable_set = set(sendable_indices)
        # Map original-index -> translated text via the local_id ordering.
        translated_by_origin: dict[int, str] = {
            sendable_indices[local_id]: translations[local_id]
            for local_id in range(len(sendable_indices))
        }
        # Per-item latency = chunk latency / sendable count. Coarse but
        # honest for now.
        per_item_ms = (
            int(elapsed_ms / max(1, len(sendable_indices))) if sendable_indices else 0
        )
        for i, item in enumerate(items):
            if i not in sendable_set:
                results.append(self._passthrough(item))
                continue
            text = (translated_by_origin.get(i) or "").strip()
            if not text:
                # Model returned empty for a non-empty input. Don't silently
                # nuke caller text — passthrough source.
                results.append(self._passthrough(item))
                continue
            results.append(
                TranslationResult(
                    text=text,
                    provider=self._provider_id,
                    cached=False,
                    latency_ms=per_item_ms,
                    correlation_id="",
                    metadata={"role": item.role, "batch_size": len(sendable_indices)},
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
                results.append(self._passthrough(item))
                continue
            prompt = _role_prompt(item.role, target_lang)
            started = time.perf_counter()
            raw = await self._generate(prompt, "{text}", {"text": value})
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            cleaned = _strip_code_fences(raw or "")
            if not cleaned:
                results.append(self._passthrough(item))
                continue
            results.append(
                TranslationResult(
                    text=cleaned,
                    provider=f"{self._provider_id}#fallback",
                    cached=False,
                    latency_ms=elapsed_ms,
                    correlation_id="",
                    metadata={"role": item.role, "batch_size": 1},
                )
            )
        return results


__all__ = ["OpenAIProvider", "TextGenerator"]
