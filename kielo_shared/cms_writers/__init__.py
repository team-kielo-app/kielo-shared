"""kielo_shared.cms_writers — Python mirror of kielo-shared/events
(Go) CMSWriterEndpoint vocabulary + the engine-side HTTP client that
calls the kielo-cms writer endpoints.

Sweep XXXXX-A (2026-06-02): cross-language SoT for the ADR-012 §D2.3
Phase 4 writer endpoints. Pre-XXXXX the kielo-learn-engine wrote
directly to `cms_<lang>.*` schemas owned by kielo-cms; post-XXXXX
those writes route through HTTP-shaped projection endpoints.

Architectural shape mirrors `kielo_shared.errors` (Sweep DDDDD-B3):

  - **CMSWriterEndpoint** typed alias (``str`` newtype).
  - **Constants** — one per registered cms-side writer endpoint.
    Wire string format: ``<resource>.<operation>.v<N>``.
  - **ALL_CMS_WRITER_ENDPOINTS** — canonical iteration order
    matching the Go-side ``AllCMSWriterEndpoints`` slice byte-for-byte.
  - **is_known_cms_writer_endpoint()** — vocabulary validator.

Cross-language parity:

  The contract test at
  ``tests/contract/cms_writer_endpoint_vocabulary_contract_test.go``
  enforces that every Go-side wire string has a matching Python
  constant + vice-versa. Adding a new endpoint on either side without
  the sibling fails the gate.

Sibling typed-vocabulary SoT modules:
  - ``kielo_shared.errors`` (Sweep DDDDD-B3) — error codes
  - ``kielo_shared.localization.contract`` (Sweep WW) — localizable fields
  - ``kielo-shared/events`` (Go) — eventtype / outboxeventtype /
    publisheventtype / cmswriterendpoint (this file)

The HTTP client itself (``CMSWritersClient``) lives in client.py
alongside the constants.
"""

from __future__ import annotations

from typing import NewType, FrozenSet

# Sweep XXXXX-A — typed alias for the cms-writer endpoint vocabulary.
# NewType keeps wire-format strings str-compatible at runtime while
# enabling static-checker discipline at the call sites.
CMSWriterEndpoint = NewType("CMSWriterEndpoint", str)


# Sweep XXXXX-A pattern-establishment endpoints — 4 endpoints covering
# 5 engine sites (the BaseWordAudioUpdate endpoint covers 2 sites via
# the `overwrite` body flag). Wire strings MUST match the Go-side
# AllCMSWriterEndpoints byte-for-byte; contract test enforces parity.

CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE: CMSWriterEndpoint = CMSWriterEndpoint(
    "grammar_concept.examples.update.v1"
)
"""PATCH /internal/klearn/grammar-concepts/{grammar_concept_id}/examples

Engine consumer: grammar_example_enrichment.py:_store_examples (site 16).
Idempotent; deterministic by grammar_concept_id; safe on retry.
"""

CMS_WRITER_BASE_WORD_AUDIO_UPDATE: CMSWriterEndpoint = CMSWriterEndpoint(
    "base_word.audio.update.v1"
)
"""PATCH /internal/klearn/base-words/{base_word_id}/audio

Engine consumer: tts_service.py:_update_base_word_audio (sites 14 + 15).
The `overwrite` body field toggles between unconditional update
(overwrite=true) and conditional-on-blank (overwrite=false, for
cache-hit replay).
"""

CMS_WRITER_BASE_WORD_MEANING_NULL: CMSWriterEndpoint = CMSWriterEndpoint(
    "base_word.meaning.null.v1"
)
"""DELETE /internal/klearn/base-words/{base_word_id}/meaning?if_current_value=<v>

Engine consumer: data_quality/base_word_meaning_checker.py:repair (site 12).
Conditional NULL — optimistic-concurrency guard via query param;
server returns {action: 'updated' | 'noop'} based on rowcount.
"""

CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL: CMSWriterEndpoint = CMSWriterEndpoint(
    "dictionary_sense.translation.null.v1"
)
"""DELETE /internal/klearn/base-words/{base_word_id}/senses/{sense_order}/translation?if_current_value=<v>

Engine consumer: data_quality/sense_translation_checker.py:repair (site 11).
Same conditional-NULL shape as BaseWordMeaningNull but on
cms_<lang>.dictionary_senses.translation; key is
(base_word_id, language_code, sense_order).
"""


# Sweep XXXXX-B (2026-06-02) — atomic-pair composite endpoint
# covering the dictionary-enrichment hot path. Replaces 4 engine
# user-path sites (2+4, 3+4, 6+7, 9) with a single cms-side
# composite transaction.

CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT: CMSWriterEndpoint = CMSWriterEndpoint(
    "base_word.translation.upsert.v1"
)


# Sweep XXXXX-C (2026-06-02) — embedding writes for cms_<lang>.base_words.
# Single + batch shapes; engine consumers at 4 sites already iterate
# per-row inside worker loops; batch endpoint collapses N RTTs to 1.

CMS_WRITER_BASE_WORD_EMBEDDING_UPDATE: CMSWriterEndpoint = CMSWriterEndpoint(
    "base_word.embedding.update.v1"
)
"""PATCH /internal/klearn/base-words/{base_word_id}/embedding

Single-row vector_embedding UPDATE. Engine consumers prefer the batch
shape below; this endpoint exists for parity.
"""

CMS_WRITER_BASE_WORD_EMBEDDING_BATCH: CMSWriterEndpoint = CMSWriterEndpoint(
    "base_word.embedding.batch.v1"
)
"""POST /internal/klearn/base-words/embeddings/batch

Batch vector_embedding UPDATE — all writes commit in a single cms-side
transaction. Request body:
  {"items": [{"base_word_id": "<uuid>", "vector": [float, ...]}]}
Response:
  {"updated": <int>, "missing": [<uuid>, ...]}

Engine consumers (all worker loops, post-translation phase):
  - internal_router.py:enrich_words (site 1)
  - internal_router.py:enrich_words_by_ids (site 5)
  - internal_router.py:enrich_words_with_translations (site 8)
  - word_enrichment.py:_run_embedding_enrichment_for_active_language (site 10)
"""


# Sweep XXXXX-D (2026-06-02) — large-payload UPSERT endpoints that
# previously executed via search-path-resolved unqualified SQL
# against cms_<lang>.{dictionary_enrichments,word_forms,dictionary_senses}.
# Site 13 (topic_list_generation INSERT cms_<target_lang>.base_words)
# migrates to the existing POST /internal/klearn/base-words endpoint
# — no new constant needed.

CMS_WRITER_DICTIONARY_ENRICHMENT_UPSERT: CMSWriterEndpoint = CMSWriterEndpoint(
    "dictionary_enrichment.upsert.v1"
)
"""PUT /internal/klearn/base-words/{base_word_id}/enrichment

Upsert dictionary_enrichments row (synonyms / antonyms / confusables /
mnemonic / paradigm / domain_tags / phrase_frames / word_cluster +
their *_source provenance fields). COALESCE-preserve on conflict
matches the pre-XXXXX-D engine helper byte-for-byte.

Engine consumer: dictionary_enrichment.py:_upsert_dictionary_enrichment (+1).
"""

CMS_WRITER_WORD_FORMS_UPSERT: CMSWriterEndpoint = CMSWriterEndpoint(
    "word_forms.upsert.v1"
)
"""PUT /internal/klearn/base-words/{base_word_id}/word-forms

Batch upsert word_forms rows. Composite PK (base_word_id, language_code,
surface_form, paradigm_slot). COALESCE-preserve on morphology; is_lemma
unconditional EXCLUDED.

Engine consumer: dictionary_enrichment.py:_upsert_word_forms (+2).
"""

CMS_WRITER_DICTIONARY_SENSE_UPSERT: CMSWriterEndpoint = CMSWriterEndpoint(
    "dictionary_sense.upsert.v1"
)
"""PUT /internal/klearn/base-words/{base_word_id}/senses

Batch upsert dictionary_senses rows. Composite PK (base_word_id,
language_code, sense_order). COALESCE-preserve on translation /
definition / usage_notes / examples / tags. Distinct from
CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT (XXXXX-B) which is the
atomic-pair composite that bundles meaning + 1 sense; this XXXXX-D
endpoint is the standalone N-sense UPSERT shape used by dictionary
enrichment.

Engine consumer: dictionary_enrichment.py:_upsert_dictionary_senses (+3).
"""
"""POST /internal/klearn/base-words/{base_word_id}/translation

Atomic composite: UPDATE base_words.meaning + UPSERT N dictionary_senses
rows in a single cms-side transaction. Preserves the Sweep BBB tx-split
invariant — the cms-side handler runs this composite as one tx, then
the engine separately commits the embedding tx after.

Request body:
  {
    "meaning": "...",                     # required string
    "only_if_blank": False,               # optional; site 9 back-fill flag
    "senses": [                           # optional list (may be empty)
      {
        "language_code": "en",
        "sense_order": 1,
        "translation": "...",
        "tags": ["gemini_one_shot", "confidence:0.85", ...],
      }
    ]
  }

Response: {"meaning_action": "updated" | "noop", "senses_upserted": <int>}

Engine consumers:
  - internal_router.py:enrich_words_by_ids sites 2+4 (DDD primary), 3+4 (opus-mt fallback)
  - internal_router.py:enrich_words_with_translations sites 6+7 (EEE-Gemini)
  - dictionary_enrichment.py:enrich_dictionary_entries site 9 (back-fill, senses=[])
"""


# Canonical iteration order — MUST match Go-side AllCMSWriterEndpoints
# byte-for-byte. Contract test enforces.
ALL_CMS_WRITER_ENDPOINTS: tuple[CMSWriterEndpoint, ...] = (
    # XXXXX-A pattern-establishment block:
    CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE,
    CMS_WRITER_BASE_WORD_AUDIO_UPDATE,
    CMS_WRITER_BASE_WORD_MEANING_NULL,
    CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL,
    # XXXXX-B atomic-pair composite block:
    CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT,
    # XXXXX-C embedding endpoints block:
    CMS_WRITER_BASE_WORD_EMBEDDING_UPDATE,
    CMS_WRITER_BASE_WORD_EMBEDDING_BATCH,
    # XXXXX-D large-payload upserts block:
    CMS_WRITER_DICTIONARY_ENRICHMENT_UPSERT,
    CMS_WRITER_WORD_FORMS_UPSERT,
    CMS_WRITER_DICTIONARY_SENSE_UPSERT,
)

# Frozen-set form for O(1) membership tests in the validator + the
# contract gate's set-equality assertion.
_ALL_CMS_WRITER_ENDPOINTS_SET: FrozenSet[str] = frozenset(
    str(e) for e in ALL_CMS_WRITER_ENDPOINTS
)


def is_known_cms_writer_endpoint(wire: str) -> bool:
    """Return True when ``wire`` is a registered CMSWriterEndpoint
    constant. Used by future client validators + the contract gate.
    """
    return wire in _ALL_CMS_WRITER_ENDPOINTS_SET


__all__ = [
    "CMSWriterEndpoint",
    "CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE",
    "CMS_WRITER_BASE_WORD_AUDIO_UPDATE",
    "CMS_WRITER_BASE_WORD_MEANING_NULL",
    "CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL",
    "CMS_WRITER_BASE_WORD_TRANSLATION_UPSERT",
    "CMS_WRITER_BASE_WORD_EMBEDDING_UPDATE",
    "CMS_WRITER_BASE_WORD_EMBEDDING_BATCH",
    "CMS_WRITER_DICTIONARY_ENRICHMENT_UPSERT",
    "CMS_WRITER_WORD_FORMS_UPSERT",
    "CMS_WRITER_DICTIONARY_SENSE_UPSERT",
    "ALL_CMS_WRITER_ENDPOINTS",
    "is_known_cms_writer_endpoint",
]
