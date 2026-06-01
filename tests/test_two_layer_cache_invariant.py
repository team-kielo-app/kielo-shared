"""Sweep EEEEE (2026-06-01): two-layer cache invariant test.

Post-AAAAA the engine localization stack has TWO cache layers:

  1. **Seam-layer cache** (cache_redis.py RedisCache + seam.py):
     - Key shape: ``kielo:i18n:{namespace}:{source_id}:{source_version}:{target}``
     - Constructed by ``Seam._cache_key(ref, target)``.
     - Resource-scoped — survives provider swaps (gemini → opus-mt → vi-fast).
     - Owned by ``Seam.translate`` / ``translate_batch``.

  2. **Provider-chain cache** (cache.py RedisCacheDecorator + _key_for):
     - Key shape: ``loc:{provider_id}:{src}:{tgt}:{role}:{sha256[:32]}``
     - Constructed by ``cache._key_for(provider_id, source_locale,
       target_locale, item)``.
     - Content-hash-scoped — survives ``source_version`` bumps when text is
       unchanged.
     - Owned by the OpenAIProvider decoration chain.

These layers are NOT overlapping — they cache different things at
different layers:

  - Seam cache hit → skip override-lookup AND provider call entirely.
  - Seam cache miss + decorator hit → skip the LLM call (saves cost)
    but still incurs 1 Redis MGET at seam + 1 Redis GET at decorator.
    Acceptable cost: ~150µs network RT vs ~500ms LLM call.
  - Both miss → 1 provider call, 2 cache writes (both layers cache).

This module pins the architectural invariant: cache keys at the two
layers are structurally disjoint (no shared prefix that could cause
collision), so the two caches CANNOT poison each other.

Honest accounting at the architectural layer: this is hardening,
not a runtime fix. Pre-EEEEE the architecture worked correctly; the
invariant was carried by implicit knowledge (the seam.py:374 doc
comment + the cache.py:48 doc comment). Post-EEEEE the invariant is
mechanically enforced — any future drift in either key shape that
introduces collision potential fails the gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from kielo_shared.localization.cache import _key_for
from kielo_shared.localization.seam import Seam, SourceRef


# --- Test fixtures -----------------------------------------------------


@dataclass
class _Item:
    """Minimal TranslationItem-shaped fixture for cache._key_for."""

    text: str
    role: str = "ui"
    cache_key: Optional[str] = None


def _seam_key(namespace: str, source_id: str, source_version: int, target: str) -> str:
    """Helper that constructs a seam cache key the same way Seam does."""
    ref = SourceRef(
        namespace=namespace,
        source_id=source_id,
        source_version=str(source_version),
        source_text="",
    )
    return Seam._cache_key(ref, target)  # pylint: disable=protected-access


# --- Key shape invariants ----------------------------------------------


def test_seam_cache_key_prefix_is_namespaced():
    """The seam cache key starts with the canonical ``kielo:i18n:`` prefix
    so it can never collide with the provider-chain cache (``loc:``).

    Anchors the Sweep EEEEE two-layer invariant: cache key prefixes are
    the disjoint-namespace mechanism.
    """
    key = _seam_key(
        namespace="engine.curriculum.track_title",
        source_id="track-123",
        source_version=5,
        target="vi",
    )
    assert key.startswith("kielo:i18n:"), (
        f"seam cache key {key!r} must start with 'kielo:i18n:' prefix"
    )


def test_provider_chain_cache_key_prefix_is_namespaced():
    """The provider-chain cache key starts with ``loc:`` prefix so it
    can never collide with the seam cache.
    """
    key = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello"),
    )
    assert key.startswith("loc:"), (
        f"provider-chain cache key {key!r} must start with 'loc:' prefix"
    )


def test_two_layer_prefixes_are_disjoint():
    """The two layers' prefixes are structurally disjoint — no string
    starts with both ``kielo:i18n:`` AND ``loc:``.

    This is the EEEEE invariant in its strongest form: collision is
    impossible at the lexical level.
    """
    SEAM_PREFIX = "kielo:i18n:"
    PROVIDER_PREFIX = "loc:"
    assert not SEAM_PREFIX.startswith(PROVIDER_PREFIX)
    assert not PROVIDER_PREFIX.startswith(SEAM_PREFIX)
    # Stronger: the first byte differs.
    assert SEAM_PREFIX[0] != PROVIDER_PREFIX[0]


# --- Cache-purpose semantic invariants ---------------------------------


def test_seam_cache_key_encodes_source_version():
    """Seam cache MUST encode source_version so a content edit
    (which bumps the version) invalidates the cached entry. Without
    this property, edits to e.g. a track title would never reach
    learners.
    """
    k_v1 = _seam_key(
        namespace="engine.curriculum.track_title",
        source_id="track-123",
        source_version=1,
        target="vi",
    )
    k_v2 = _seam_key(
        namespace="engine.curriculum.track_title",
        source_id="track-123",
        source_version=2,
        target="vi",
    )
    assert k_v1 != k_v2, (
        "seam cache key MUST differ between source_version=1 and =2; "
        "without this property, content edits would be permanently cached"
    )


def test_seam_cache_key_encodes_target_locale():
    """Seam cache MUST encode target_locale so vi and sv learners
    get different cached entries.
    """
    k_vi = _seam_key(
        namespace="engine.curriculum.track_title",
        source_id="track-123",
        source_version=1,
        target="vi",
    )
    k_sv = _seam_key(
        namespace="engine.curriculum.track_title",
        source_id="track-123",
        source_version=1,
        target="sv",
    )
    assert k_vi != k_sv


def test_provider_chain_cache_key_encodes_content_hash():
    """Provider-chain cache key MUST encode a content-hash
    (sha256[:32]) of the text. This is what allows the layer to
    survive source_version bumps when the text is actually unchanged
    (e.g. an admin re-saves a row without editing).
    """
    key = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello world"),
    )
    expected_hash = hashlib.sha256(b"hello world").hexdigest()[:32]
    assert expected_hash in key, (
        f"provider-chain cache key {key!r} must encode sha256 of text"
    )


def test_provider_chain_cache_key_changes_on_text_edit():
    """Edit the text → key changes."""
    k1 = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello"),
    )
    k2 = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello world"),
    )
    assert k1 != k2, "edit-text → cache-key-change invariant violated"


def test_provider_chain_cache_key_stable_on_text_unchanged():
    """Same text → same key. This is the architectural reason for the
    provider-chain layer: when source_version bumps but text is
    unchanged, the cache survives the version change and skips the LLM.
    """
    k1 = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello"),
    )
    k2 = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="hello"),
    )
    assert k1 == k2


# --- Adversarial sanity checks -----------------------------------------


def test_seam_key_disjoint_from_provider_key_under_adversarial_input():
    """Even under maximally-similar input shapes, the two cache keys
    cannot collide. Strong invariant: the prefixes are different so
    no lexical accident can map both to the same Redis slot.
    """
    seam_key = _seam_key(
        namespace="loc",
        source_id="openai-gpt-4:en:vi:ui:abc",
        source_version=1,
        target="vi",
    )
    provider_key = _key_for(
        provider_id="openai-gpt-4",
        source_locale="en",
        target_locale="vi",
        item=_Item(text="engine.curriculum.track_title:track-123:1:vi"),
    )
    assert seam_key != provider_key
    # Stronger — neither starts with the other's prefix.
    assert not seam_key.startswith("loc:")
    assert not provider_key.startswith("kielo:i18n:")


def test_seam_key_with_provider_id_in_source_id_does_not_collide():
    """Adversarial: even if some future namespace pattern embeds the
    provider_id in source_id, the prefix invariant holds.
    """
    seam_key = _seam_key(
        namespace="openai-gpt-4",
        source_id="en:vi:ui:somehash",
        source_version=1,
        target="vi",
    )
    assert seam_key.startswith("kielo:i18n:")
    # Reading the seam key as if it were a provider key should fail
    # because it doesn't start with `loc:`.
    assert ":openai-gpt-4:" in seam_key  # the provider_id IS embedded
    # But the canonical prefix is still kielo:i18n:.
    assert seam_key != f"loc:openai-gpt-4:en:vi:ui:somehash"


# --- TTL semantics -----------------------------------------------------


def test_seam_layer_owns_resource_scope_semantics():
    """Sweep EEEEE documents the semantic split: when an admin updates
    a row's TEXT (which bumps source_version), the seam cache MISSES
    on the next read; if the new text happens to equal a previously-
    translated text under the same locale, the provider-chain cache
    HITS and avoids the LLM call. This test pins the keys to prove
    the architectural property is achievable.

    Scenario:
      - source_version=1, text="hello" -> translated "xin chào"
      - admin edits to text="hi" (version=2)
      - admin edits BACK to text="hello" (version=3)

    Expected:
      - seam key v1 != seam key v3 (so v3 must re-translate via the
        provider chain)
      - provider-chain key for v1 text == provider-chain key for v3
        text (so the LLM call is skipped on v3 because the content-
        hash is the same)
    """
    seam_v1 = _seam_key("a.b.c", "row-1", 1, "vi")
    seam_v3 = _seam_key("a.b.c", "row-1", 3, "vi")
    assert seam_v1 != seam_v3

    provider_v1 = _key_for(
        provider_id="p", source_locale="en", target_locale="vi",
        item=_Item(text="hello"),
    )
    provider_v3 = _key_for(
        provider_id="p", source_locale="en", target_locale="vi",
        item=_Item(text="hello"),
    )
    assert provider_v1 == provider_v3
