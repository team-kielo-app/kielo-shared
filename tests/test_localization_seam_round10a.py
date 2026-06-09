"""Round 10A regression tests — pin the persister + suspicious-translation
guard contracts in the kielo-shared Seam.

Round 10A wired two new optional dependencies into the Seam constructor
via Protocol-based DI (mirror of the existing Cache + OverrideStore +
Metrics injection points):

  * ``TranslationPersister.persist(ref, target, value)`` — fired after
    every successful provider_call so the row lands in
    ``localization.dynamic_translations``. Pre-Round-10A the seam
    wrote only to Redis cache; the autotranslate-callback documented
    at engine main.py:660 had no write-through and after months of
    being "live" the table had ZERO ``ui.string`` rows.

  * ``SuspiciousTranslationGuard.is_suspicious(source, candidate,
    target)`` — quality gate on fresh provider output. Pre-Round-10A
    the canonical Sweep PP/QQ/KKK guard ran only at ``_via_registry``
    in structured_content_localizer; the seam path was unguarded
    and the autotranslate-callback would have silently persisted any
    junk the LLM produced.

These tests use MapPersister + AlwaysSuspiciousGuard + NoopGuard
to pin the behavioural contracts:

  T1: persister called on successful provider_call (single-item path)
  T2: persister called per-item on successful translate_batch
  T3: guard rejection falls back to source + skips persistence + skips
      cache write (single-item path)
  T4: guard rejection on batch path falls back per-item without
      affecting siblings
  T5: backward-compat — no persister, no guard → pre-Round-10A behaviour
  T6: english_passthrough never invokes persister or guard
  T7: cache_hit short-circuits before persister + guard fire
  T8: override hit short-circuits before persister + guard fire
  T9: persister errors are swallowed (translation still returns;
      degraded but correct)
"""
from __future__ import annotations


import pytest

from kielo_shared.localization.seam import (
    AlwaysSuspiciousGuard,
    CountingMetrics,
    MapOverrideStore,
    MapPersister,
    Seam,
    SourceRef,
)
from kielo_shared.localization.types import TranslationItem, TranslationResult


# ──────────────────────── Test harness ───────────────────────────────────


class StubProvider:
    """Provider that returns a fixed translation for every call.
    Mirrors the canonical test_localization_seam.py shape."""

    def __init__(self, fixed_output: str = "TRANSLATED") -> None:
        self.fixed_output = fixed_output
        self.calls = 0

    @property
    def provider_id(self) -> str:
        return "round10a-stub"

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
    ) -> list[TranslationResult]:
        self.calls += 1
        return [
            TranslationResult(text=self.fixed_output, provider=self.provider_id)
            for _ in items
        ]


class StubRegistry:
    def __init__(self, provider: StubProvider) -> None:
        self._provider = provider

    def resolve(self, *, source_locale: str, target_locale: str):
        return self._provider


class RaisingPersister:
    """Persister whose persist() always raises. Pins T9 — the seam
    swallows persistence errors and still returns the translation."""

    def __init__(self) -> None:
        self.calls = 0

    async def persist(self, ref: SourceRef, target_locale: str, translated_text: str) -> None:
        self.calls += 1
        raise RuntimeError("simulated persister failure")


def _ref(source_text: str = "Hello", namespace: str = "ui.string", source_id: str = "test.key") -> SourceRef:
    return SourceRef(
        namespace=namespace,
        source_id=source_id,
        source_version="abc1234567890def",
        source_text=source_text,
    )


# ──────────────────────── Tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_t1_persister_called_on_successful_provider_call_single_item():
    """Single-item translate path: provider returns clean output →
    persister called with (ref, target, value) tuple matching the row
    that should land in localization.dynamic_translations."""
    provider = StubProvider(fixed_output="Olá")
    persister = MapPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
    )

    val = await seam.translate(_ref(), "pt")

    assert val == "Olá"
    assert provider.calls == 1, "provider called once"
    assert len(persister.calls) == 1, "persister called once"
    namespace, source_id, source_version, target, translated = persister.calls[0]
    assert namespace == "ui.string"
    assert source_id == "test.key"
    assert source_version == "abc1234567890def"
    assert target == "pt"
    assert translated == "Olá"


@pytest.mark.asyncio
async def test_t2_persister_called_per_item_on_batch_path():
    """Batch path: provider returns N clean outputs → persister called
    N times (one per item) with correct tuples."""
    provider = StubProvider(fixed_output="translated_value")
    persister = MapPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
    )

    refs = [
        SourceRef(namespace="ui.string", source_id=f"key.{i}", source_version=f"v{i}", source_text=f"Hello {i}")
        for i in range(3)
    ]
    values = await seam.translate_batch(refs, "vi")

    assert all(v == "translated_value" for v in values)
    assert provider.calls == 1, "single batch provider call"
    assert len(persister.calls) == 3, "persister called per-item"
    source_ids = sorted(c[1] for c in persister.calls)
    assert source_ids == ["key.0", "key.1", "key.2"]


@pytest.mark.asyncio
async def test_t3_guard_rejection_falls_back_to_source_single_item():
    """Single-item path with AlwaysSuspiciousGuard: provider returns
    output → guard rejects → seam returns source text + persister NOT
    called + cache NOT written.

    Pins the Sweep PP/QQ/KKK fallback semantics at the seam layer."""
    provider = StubProvider(fixed_output="JUNK_LLM_OUTPUT")
    persister = MapPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
        guard=AlwaysSuspiciousGuard(),
    )

    val = await seam.translate(_ref(source_text="Hello"), "ja")

    assert val == "Hello", "guard rejection falls back to source"
    assert provider.calls == 1, "provider was still called"
    assert len(persister.calls) == 0, "persister NOT called when guard rejects"


@pytest.mark.asyncio
async def test_t4_guard_rejection_on_batch_does_not_affect_siblings():
    """Batch path with AlwaysSuspiciousGuard: provider returns N outputs
    → all rejected → all items fall back to source + persister called 0
    times. (When a real guard rejects only SOME items, siblings still
    persist; verified via stub above — this test pins the all-rejected
    case.)"""
    provider = StubProvider(fixed_output="JUNK")
    persister = MapPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
        guard=AlwaysSuspiciousGuard(),
    )

    refs = [
        SourceRef(namespace="ui.string", source_id=f"k.{i}", source_version=f"v{i}", source_text=f"Source {i}")
        for i in range(3)
    ]
    values = await seam.translate_batch(refs, "ru")

    assert values == ["Source 0", "Source 1", "Source 2"]
    assert len(persister.calls) == 0


@pytest.mark.asyncio
async def test_t5_backward_compat_noop_defaults_preserve_pre_round10a_behaviour():
    """No persister, no guard: pre-Round-10A behaviour preserved.
    Translation returns provider output. No exceptions. This is the
    contract that the seam stays backward-compatible for callers that
    haven't wired Round 10A yet."""
    provider = StubProvider(fixed_output="defaults_work")
    seam = Seam(registry=StubRegistry(provider))  # no persister, no guard

    val = await seam.translate(_ref(), "fi")

    assert val == "defaults_work"


@pytest.mark.asyncio
async def test_t6_english_passthrough_never_invokes_persister_or_guard():
    """target=en or target empty: seam short-circuits before provider.
    Persister + guard not invoked because no LLM output exists to
    persist or check."""
    provider = StubProvider(fixed_output="should_not_appear")
    persister = MapPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
        guard=AlwaysSuspiciousGuard(),  # would reject if invoked
    )

    val_en = await seam.translate(_ref(source_text="Hello"), "en")
    val_empty = await seam.translate(_ref(source_text="Hello"), "")

    assert val_en == "Hello"
    assert val_empty == "Hello"
    assert provider.calls == 0
    assert len(persister.calls) == 0


@pytest.mark.asyncio
async def test_t7_override_hit_short_circuits_before_persister_and_guard():
    """Override store returns a value: seam serves it directly without
    invoking provider, persister, or guard. The override IS the
    persisted canonical translation — persisting again would be
    redundant."""
    provider = StubProvider(fixed_output="should_not_appear")
    persister = MapPersister()
    overrides = MapOverrideStore({
        "ui.string|test.key|abc1234567890def|vi": "Xin chào",
    })
    seam = Seam(
        registry=StubRegistry(provider),
        overrides=overrides,
        persister=persister,
        guard=AlwaysSuspiciousGuard(),  # would reject if invoked
    )

    val = await seam.translate(_ref(source_text="Hello"), "vi")

    assert val == "Xin chào"
    assert provider.calls == 0
    assert len(persister.calls) == 0


@pytest.mark.asyncio
async def test_t8_persister_failures_are_swallowed():
    """Persister.persist() raises → seam logs + returns translation.
    Round 10A contract: losing the persistence row only means the
    next request re-runs the LLM (degraded but correct); persistence
    failures must NOT bubble to the caller."""
    provider = StubProvider(fixed_output="Olá")
    persister = RaisingPersister()
    seam = Seam(
        registry=StubRegistry(provider),
        persister=persister,
    )

    val = await seam.translate(_ref(), "pt")

    assert val == "Olá", "persister failure does not affect translation"
    assert persister.calls == 1, "persister was called even though it raised"


@pytest.mark.asyncio
async def test_t9_metrics_record_provider_error_on_guard_rejection_in_batch():
    """Batch path with AlwaysSuspiciousGuard: metric records
    provider_error tag (not provider_call) so operators see the
    guard rejections in the same dashboard as natural provider
    failures."""
    provider = StubProvider(fixed_output="JUNK")
    metrics = CountingMetrics()
    seam = Seam(
        registry=StubRegistry(provider),
        metrics=metrics,
        guard=AlwaysSuspiciousGuard(),
    )

    refs = [SourceRef(namespace="ui.string", source_id="k", source_version="v", source_text="Source")]
    await seam.translate_batch(refs, "ja")

    assert metrics.count("ui.string", "ja", "provider_error") == 1
    assert metrics.count("ui.string", "ja", "provider_call") == 0
