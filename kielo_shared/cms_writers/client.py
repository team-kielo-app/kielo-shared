"""kielo_shared.cms_writers.client — HTTP-shaped client for the
kielo-cms writer endpoints registered by the CMSWriterEndpoint SoT.

Sweep XXXXX-A (2026-06-02): canonical client for the ADR-012 §D2.3
Phase 4 migration. Engine + future Python services use this client
instead of writing directly to cms_<lang>.* schemas.

Architectural pairing:
  - Endpoint vocabulary: kielo_shared.cms_writers (CMSWriterEndpoint
    constants + AllCMSWriterEndpoints iteration order)
  - This module (client.py): HTTP client that consumes those constants

The client deliberately exposes ONE method per endpoint constant
(rather than a generic execute-by-constant function) so the call site
is type-annotated end-to-end. Mirrors the Sweep VVVVV pattern
(typed UUID parameters; nil-safe).

Returns:
  - For unconditional writers: None on success or raises httpx.HTTPError
  - For conditional writers (the *NullIf endpoints): a typed
    CMSWriterUpdateResult enum value (UPDATED / NOOP) so the caller
    can branch on outcome without inferring from status codes
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from uuid import UUID

import httpx

from kielo_shared.http import internal_client_async

from . import (
    CMS_WRITER_BASE_WORD_AUDIO_UPDATE,
    CMS_WRITER_BASE_WORD_EMBEDDING_BATCH,
    CMS_WRITER_BASE_WORD_EMBEDDING_UPDATE,
    CMS_WRITER_BASE_WORD_MEANING_NULL,
    CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT,
    CMS_WRITER_DICTIONARY_ENRICHMENT_UPSERT,
    CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL,
    CMS_WRITER_DICTIONARY_SENSE_UPSERT,
    CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE,
    CMS_WRITER_WORD_FORMS_UPSERT,
)

logger = logging.getLogger(__name__)


class CMSWriterUpdateResult(str, Enum):
    """Two-value enum encoding whether a conditional write fired or
    no-op'd. Mirrors the Go-side repository.CMSWriterUpdateResult."""

    UPDATED = "updated"
    NOOP = "noop"


@dataclass(frozen=True)
class BaseWordTranslationResult:
    """Sweep XXXXX-B return shape for upsert_base_word_translation.
    Mirrors the cms-side repository.BaseWordTranslationResult."""

    meaning_action: CMSWriterUpdateResult
    senses_upserted: int


@dataclass(frozen=True)
class BaseWordEmbeddingBatchResult:
    """Sweep XXXXX-C return shape for update_base_word_embeddings_batch.
    Mirrors the cms-side repository.BaseWordEmbeddingBatchResult."""

    updated: int
    missing: list[str]  # base_word_ids that didn't resolve in cms_<lang>.base_words


@dataclass(frozen=True)
class CMSWriterNotFoundError(Exception):
    """Raised when a writer's target row doesn't exist (HTTP 404 from
    the cms-side handler). Distinct from other HTTP errors so the
    caller can branch on the row-missing case."""

    endpoint: str
    resource_id: str

    def __str__(self) -> str:
        return f"cms writer {self.endpoint}: row {self.resource_id} not found"


class CMSWritersClient:
    """HTTP client for the kielo-cms writer endpoints registered by
    the CMSWriterEndpoint SoT.

    The client uses the canonical kielo_shared.http.internal_client_async
    hook chain (trace context propagation + active-language header
    forwarding + X-Internal-API-Key default) so endpoint behavior is
    consistent with the rest of the engine's HTTP surface.

    Active-language requirement: the kielo-cms writer routes use
    middleware.RequireActiveLanguageWithOptions(AllowInternalAPIKeyBypass=false),
    meaning every call MUST carry an active learning language in the
    request (via the X-Kielo-Learning-Language header or the
    learning_language_code query param). The internal_client_async
    hook chain handles this automatically when the caller's context
    carries `db_utils.WithLanguage(ctx, learning_language_code)`.
    """

    def __init__(
        self,
        cms_service_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.cms_service_url = cms_service_url.rstrip("/")
        self.api_key = api_key
        self._timeout = timeout
        self._client = internal_client_async(
            api_key=api_key,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------
    # Sweep XXXXX-A pattern-establishment endpoints
    # ------------------------------------------------------------

    async def update_grammar_concept_examples(
        self,
        grammar_concept_id: UUID,
        example_sentences: Any,
    ) -> None:
        """PATCH /internal/klearn/grammar-concepts/{id}/examples.

        Engine consumer: grammar_example_enrichment.py:_store_examples
        (site 16). CMSWriterEndpoint:
        CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE.

        Raises CMSWriterNotFoundError on 404; other HTTP errors raise
        httpx.HTTPStatusError.
        """
        url = (
            f"{self.cms_service_url}/internal/klearn/grammar-concepts/"
            f"{grammar_concept_id}/examples"
        )
        payload = {"example_sentences": example_sentences}
        response = await self._client.patch(url, json=payload)
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE,
                resource_id=str(grammar_concept_id),
            )
        response.raise_for_status()

    async def update_base_word_audio(
        self,
        base_word_id: UUID,
        audio_url: str,
        *,
        overwrite: bool,
    ) -> CMSWriterUpdateResult:
        """PATCH /internal/klearn/base-words/{id}/audio.

        Engine consumers: tts_service.py:_update_base_word_audio
        (sites 14 + 15). CMSWriterEndpoint:
        CMS_WRITER_BASE_WORD_AUDIO_UPDATE.

        The `overwrite` kwarg toggles between unconditional update
        (overwrite=True, default for fresh TTS jobs) and
        conditional-on-blank (overwrite=False, for cache-hit replay
        that preserves admin-set overrides).

        Returns:
          - CMSWriterUpdateResult.UPDATED when the row's audio_url
            was changed
          - CMSWriterUpdateResult.NOOP when overwrite=False AND the
            row already had a non-empty audio_url
          - Raises CMSWriterNotFoundError on 404
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/audio"
        payload = {"audio_url": audio_url, "overwrite": overwrite}
        response = await self._client.patch(url, json=payload)
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_BASE_WORD_AUDIO_UPDATE,
                resource_id=str(base_word_id),
            )
        response.raise_for_status()
        body = response.json()
        return CMSWriterUpdateResult(body["action"])

    async def null_base_word_meaning_if(
        self,
        base_word_id: UUID,
        if_current_value: str,
    ) -> CMSWriterUpdateResult:
        """DELETE /internal/klearn/base-words/{id}/meaning?if_current_value=<v>.

        Engine consumer: data_quality/base_word_meaning_checker.py:repair
        (site 12). CMSWriterEndpoint: CMS_WRITER_BASE_WORD_MEANING_NULL.

        Conditional NULL — `if_current_value` is the optimistic-
        concurrency guard. Server returns UPDATED when the row's
        current meaning matched (write fired) or NOOP when the row's
        current meaning differs (another writer raced and the
        data-quality engine should report the issue as already
        resolved). Raises CMSWriterNotFoundError on 404.
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/meaning"
        response = await self._client.delete(
            url, params={"if_current_value": if_current_value}
        )
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_BASE_WORD_MEANING_NULL,
                resource_id=str(base_word_id),
            )
        response.raise_for_status()
        body = response.json()
        return CMSWriterUpdateResult(body["action"])

    async def upsert_base_word_translation(
        self,
        base_word_id: UUID,
        meaning: str,
        *,
        senses: Optional[list[dict[str, Any]]] = None,
        only_if_blank: bool = False,
    ) -> "BaseWordTranslationResult":
        """POST /internal/klearn/base-words/{id}/translation.

        Sweep XXXXX-B atomic-pair composite endpoint. UPDATEs
        base_words.meaning + UPSERTs N dictionary_senses rows in a
        single cms-side transaction.

        Engine consumers:
          - internal_router.py:enrich_words_by_ids sites 2+4, 3+4
          - internal_router.py:enrich_words_with_translations sites 6+7
          - dictionary_enrichment.py:enrich_dictionary_entries site 9

        Args:
          base_word_id: target cms_<lang>.base_words.base_word_id
          meaning: the English gloss to write to base_words.meaning
          senses: optional list of {language_code, sense_order,
            translation, tags} dicts mirroring the pre-XXXXX-B
            INSERT ... ON CONFLICT shape. Empty/omitted = no sense
            writes (site 9 back-fill case).
          only_if_blank: when True, the meaning UPDATE is conditional —
            only writes when the current value is NULL or empty.
            Site 9 (dictionary_enrichment back-fill) sets this True;
            other call sites pass False.

        Returns:
          BaseWordTranslationResult with .meaning_action
          (CMSWriterUpdateResult enum) + .senses_upserted (int).

        Raises:
          CMSWriterNotFoundError on 404
          httpx.HTTPStatusError on other failures
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/translation"
        payload: dict[str, Any] = {
            "meaning": meaning,
            "only_if_blank": only_if_blank,
            "senses": senses or [],
        }
        response = await self._client.post(url, json=payload)
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT,
                resource_id=str(base_word_id),
            )
        response.raise_for_status()
        body = response.json()
        return BaseWordTranslationResult(
            meaning_action=CMSWriterUpdateResult(body["meaning_action"]),
            senses_upserted=int(body.get("senses_upserted", 0)),
        )

    async def update_base_word_embedding(
        self,
        base_word_id: UUID,
        vector: list[float],
    ) -> None:
        """PATCH /internal/klearn/base-words/{id}/embedding (single).

        Single-row vector_embedding write. Engine consumers prefer
        the batch shape below; this method exists for parity.

        CMSWriterEndpoint: base_word.embedding.update.v1
        Raises CMSWriterNotFoundError on 404.
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/embedding"
        response = await self._client.patch(url, json={"vector": vector})
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_BASE_WORD_EMBEDDING_UPDATE,
                resource_id=str(base_word_id),
            )
        response.raise_for_status()

    async def update_base_word_embeddings_batch(
        self,
        items: list[dict[str, Any]],
    ) -> "BaseWordEmbeddingBatchResult":
        """POST /internal/klearn/base-words/embeddings/batch.

        Sweep XXXXX-C N-RTT collapse — all writes commit atomically
        in a single cms-side transaction. Engine consumers (4 worker
        loops) replace per-row HTTP calls with one batch call.

        Args:
          items: list of {"base_word_id": str, "vector": list[float]}.
            Empty items list is a valid no-op.

        Returns BaseWordEmbeddingBatchResult with .updated count and
        .missing list of base_word_ids that didn't resolve in
        cms_<lang>.base_words. Missing IDs are NOT errors — engine
        callers log them but the batch still commits successfully
        for the items that DID resolve.

        CMSWriterEndpoint: base_word.embedding.batch.v1
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/embeddings/batch"
        response = await self._client.post(url, json={"items": items})
        response.raise_for_status()
        body = response.json()
        return BaseWordEmbeddingBatchResult(
            updated=int(body.get("updated", 0)),
            missing=list(body.get("missing") or []),
        )

    async def upsert_dictionary_enrichment(
        self,
        base_word_id: UUID,
        language_code: str,
        payload: dict[str, Any],
    ) -> None:
        """PUT /internal/klearn/base-words/{id}/enrichment.

        Sweep XXXXX-D — UPSERTs dictionary_enrichments row with
        COALESCE-preserve semantics. The `payload` dict is the engine's
        DictionaryEnrichmentPayload converted to JSON-shape (synonyms /
        antonyms / confusables / mnemonic / paradigm / domain_tags /
        phrase_frames / word_cluster + *_source provenance fields).

        CMSWriterEndpoint: dictionary_enrichment.upsert.v1
        """
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/enrichment"
        body = {"language_code": language_code, **payload}
        response = await self._client.put(url, json=body)
        response.raise_for_status()

    async def upsert_word_forms(
        self,
        base_word_id: UUID,
        forms: list[dict[str, Any]],
    ) -> int:
        """PUT /internal/klearn/base-words/{id}/word-forms.

        Sweep XXXXX-D — batch UPSERTs word_forms rows (composite PK
        base_word_id, language_code, surface_form, paradigm_slot).
        Each form dict: {language_code, surface_form, morphology?,
        paradigm_slot, is_lemma}.

        Returns the row count touched. Empty `forms` returns 0
        without an HTTP call.

        CMSWriterEndpoint: word_forms.upsert.v1
        """
        if not forms:
            return 0
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/word-forms"
        response = await self._client.put(url, json={"forms": forms})
        response.raise_for_status()
        body = response.json()
        return int(body.get("updated", 0))

    async def upsert_dictionary_senses(
        self,
        base_word_id: UUID,
        senses: list[dict[str, Any]],
    ) -> int:
        """PUT /internal/klearn/base-words/{id}/senses.

        Sweep XXXXX-D — batch UPSERTs dictionary_senses rows (composite
        PK base_word_id, language_code, sense_order). Each sense dict:
        {language_code, sense_order, translation?, definition?,
         usage_notes?, examples?, tags?}. examples + tags are JSON-shape.

        Distinct from upsert_base_word_translation (XXXXX-B) which is
        the atomic-pair composite that ALSO writes base_words.meaning;
        this XXXXX-D method writes ONLY the senses table.

        Returns the row count touched. Empty `senses` returns 0
        without an HTTP call.

        CMSWriterEndpoint: dictionary_sense.upsert.v1
        """
        if not senses:
            return 0
        url = f"{self.cms_service_url}/internal/klearn/base-words/{base_word_id}/senses"
        response = await self._client.put(url, json={"senses": senses})
        response.raise_for_status()
        body = response.json()
        return int(body.get("updated", 0))

    async def null_dictionary_sense_translation_if(
        self,
        base_word_id: UUID,
        language_code: str,
        sense_order: int,
        if_current_value: str,
    ) -> CMSWriterUpdateResult:
        """DELETE /internal/klearn/base-words/{id}/senses/{sense_order}/translation?
        language_code=<v>&if_current_value=<v>.

        Engine consumer: data_quality/sense_translation_checker.py:repair
        (site 11). CMSWriterEndpoint:
        CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL.

        The dictionary_senses row is uniquely keyed by
        (base_word_id, language_code, sense_order). Conditional-NULL
        with optimistic-concurrency guard via if_current_value.
        Returns UPDATED / NOOP same shape as null_base_word_meaning_if.
        Raises CMSWriterNotFoundError on 404.
        """
        url = (
            f"{self.cms_service_url}/internal/klearn/base-words/"
            f"{base_word_id}/senses/{sense_order}/translation"
        )
        response = await self._client.delete(
            url,
            params={
                "language_code": language_code,
                "if_current_value": if_current_value,
            },
        )
        if response.status_code == 404:
            raise CMSWriterNotFoundError(
                endpoint=CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL,
                resource_id=f"{base_word_id}/senses/{sense_order}",
            )
        response.raise_for_status()
        body = response.json()
        return CMSWriterUpdateResult(body["action"])


__all__ = [
    "CMSWritersClient",
    "CMSWriterUpdateResult",
    "CMSWriterNotFoundError",
    "BaseWordTranslationResult",
    "BaseWordEmbeddingBatchResult",
]
