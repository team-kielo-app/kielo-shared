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


# Canonical iteration order — MUST match Go-side AllCMSWriterEndpoints
# byte-for-byte. Contract test enforces.
ALL_CMS_WRITER_ENDPOINTS: tuple[CMSWriterEndpoint, ...] = (
    # XXXXX-A pattern-establishment block:
    CMS_WRITER_GRAMMAR_CONCEPT_EXAMPLES_UPDATE,
    CMS_WRITER_BASE_WORD_AUDIO_UPDATE,
    CMS_WRITER_BASE_WORD_MEANING_NULL,
    CMS_WRITER_DICTIONARY_SENSE_TRANSLATION_NULL,
    # XXXXX-B/C/D blocks queued; append in shipment order.
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
    "ALL_CMS_WRITER_ENDPOINTS",
    "is_known_cms_writer_endpoint",
]
