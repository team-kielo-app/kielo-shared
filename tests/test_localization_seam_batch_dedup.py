"""Intra-batch dedup on the seam's provider fan-out.

A local roadmap-lesson run translated the same source strings more than
once inside a single request. The seam's cross-call single-flight
(``Seam._inflight``) can't help there: it keys on cache_key and only
guards the per-key ``translate()`` path, while ``translate_batch`` built
one provider item per ref unconditionally.

Duplicates are normal for real callers. ``localize_text_via_seam_batch``
derives source_id from the resource, so one string shared by several
resources (step instructions, a base word cited by several exercises,
repeated CTA copy) yields distinct cache_keys with identical text — and
a caller may also list the same resource twice.

Since the provider translates purely from (text, role, source_locale,
target_locale), refs sharing that tuple can only get the same answer.
The batch now collapses them to one item and fans the result back out.
The alignment tests below are the load-bearing ones: a fan-out that
mis-maps would hand a learner another learner's string.
"""

from __future__ import annotations

import pytest

from kielo_shared.localization.seam import (
    MapPersister,
    Seam,
    SourceRef,
)
from kielo_shared.localization.types import TranslationItem, TranslationResult


class EchoProvider:
    """Returns a per-item deterministic output so a mis-mapped fan-out
    shows up as a wrong value, not just a wrong call count."""

    def __init__(self) -> None:
        self.calls = 0
        self.received: list[list[tuple[str, str]]] = []

    @property
    def provider_id(self) -> str:
        return "echo-stub"

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        self.calls += 1
        self.received.append([(i.text, str(i.role)) for i in items])
        return [
            TranslationResult(
                text=f"{target_locale}:{item.text}", provider=self.provider_id
            )
            for item in items
        ]


class ShortProvider(EchoProvider):
    """Returns one result fewer than asked — pins that the length check
    compares against the DEDUPED item list, not the original ref list."""

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        results = await super().translate_batch(
            items, source_locale=source_locale, target_locale=target_locale
        )
        return results[:-1]


class StubRegistry:
    def __init__(self, provider: EchoProvider) -> None:
        self._provider = provider

    def resolve(self, *, source_locale: str, target_locale: str):
        return self._provider


def _ref(text: str, source_id: str, role: str = "plain") -> SourceRef:
    # source_version derives from the text in production
    # (source_version_from_text), so equal text implies equal version.
    return SourceRef(
        namespace="ui.string",
        source_id=source_id,
        source_version=f"v-{abs(hash(text)) % 10**12:012d}",
        source_text=text,
        role=role,
    )


@pytest.mark.asyncio
async def test_same_text_under_different_source_ids_costs_one_provider_item():
    provider = EchoProvider()
    persister = MapPersister()
    seam = Seam(registry=StubRegistry(provider), persister=persister)

    refs = [_ref("Choose the correct form", f"step.{i}") for i in range(4)]
    values = await seam.translate_batch(refs, "vi")

    assert values == ["vi:Choose the correct form"] * 4
    assert provider.calls == 1
    assert provider.received[0] == [("Choose the correct form", "plain")], (
        "four refs sharing one string must reach the provider as one item"
    )
    # Distinct cache_keys, so each still gets its own dynamic_translations row.
    assert sorted(c[1] for c in persister.calls) == [
        "step.0",
        "step.1",
        "step.2",
        "step.3",
    ]


@pytest.mark.asyncio
async def test_identical_ref_listed_twice_persists_once():
    provider = EchoProvider()
    persister = MapPersister()
    seam = Seam(registry=StubRegistry(provider), persister=persister)

    ref = _ref("Hyvä!", "praise.good")
    values = await seam.translate_batch([ref, ref], "vi")

    assert values == ["vi:Hyvä!", "vi:Hyvä!"]
    assert provider.calls == 1
    assert len(provider.received[0]) == 1
    assert len(persister.calls) == 1, (
        "one cache_key means one row; persisting twice is a duplicate upsert"
    )


@pytest.mark.asyncio
async def test_fan_out_maps_every_position_to_its_own_source():
    """The alignment regression: interleaved duplicates must not shift
    later results onto the wrong ref."""
    provider = EchoProvider()
    seam = Seam(registry=StubRegistry(provider))

    texts = ["Alpha", "Beta", "Alpha", "Gamma", "Beta", "Alpha"]
    refs = [_ref(t, f"key.{i}") for i, t in enumerate(texts)]
    values = await seam.translate_batch(refs, "it")

    assert values == [f"it:{t}" for t in texts]
    assert provider.received[0] == [
        ("Alpha", "plain"),
        ("Beta", "plain"),
        ("Gamma", "plain"),
    ], "deduped items keep first-occurrence order"


@pytest.mark.asyncio
async def test_same_text_different_roles_is_not_collapsed():
    # role selects the prompt flavor, so it changes the expected output.
    provider = EchoProvider()
    seam = Seam(registry=StubRegistry(provider))

    refs = [
        _ref("kirja", "word.1", role="plain"),
        _ref("kirja", "word.2", role="gloss"),
    ]
    await seam.translate_batch(refs, "vi")

    assert provider.received[0] == [("kirja", "plain"), ("kirja", "gloss")]


@pytest.mark.asyncio
async def test_all_distinct_texts_are_untouched():
    provider = EchoProvider()
    seam = Seam(registry=StubRegistry(provider))

    texts = ["one", "two", "three"]
    refs = [_ref(t, f"key.{i}") for i, t in enumerate(texts)]
    values = await seam.translate_batch(refs, "vi")

    assert values == [f"vi:{t}" for t in texts]
    assert provider.received[0] == [(t, "plain") for t in texts]


@pytest.mark.asyncio
async def test_length_mismatch_is_measured_against_deduped_items():
    """Pre-dedup the check was len(results) != len(remaining). With
    dedup that comparison is wrong in both directions: a correct
    provider would look short, and a genuinely short response could
    look correct. Falling back to source for every ref is the
    contract on a provider bug."""
    provider = ShortProvider()
    seam = Seam(registry=StubRegistry(provider))

    refs = [
        _ref("Alpha", "key.0"),
        _ref("Alpha", "key.1"),
        _ref("Beta", "key.2"),
    ]
    values = await seam.translate_batch(refs, "vi")

    assert values == ["Alpha", "Alpha", "Beta"], "source fallback, never empty"
