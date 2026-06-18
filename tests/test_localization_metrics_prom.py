"""Tests for kielo_shared.localization.metrics_prom — parity with the
Go-side metricsprom adapter."""

from __future__ import annotations

import pytest
from prometheus_client import CollectorRegistry

from kielo_shared.localization.metrics_prom import (
    COUNTER_NAME,
    COUNTER_SAMPLE_NAME,
    LABEL_NAMES,
    PromMetrics,
)


def _counter_value(reg: CollectorRegistry, namespace: str, target: str, source: str) -> float:
    """Pull the value of a specific labelled counter out of a registry.

    Uses COUNTER_SAMPLE_NAME (the on-wire `_total`-suffixed name) rather
    than COUNTER_NAME (the bare family name prometheus_client expects in
    the constructor).
    """
    return reg.get_sample_value(
        COUNTER_SAMPLE_NAME,
        {"namespace": namespace, "target_locale": target, "source": source},
    ) or 0.0


def test_label_names_pinned() -> None:
    # Pin label order — Go side asserts the same shape; dashboards
    # depend on the labels being identical across services.
    assert LABEL_NAMES == ("namespace", "target_locale", "source")


def test_record_increments_counter() -> None:
    reg = CollectorRegistry()
    metrics = PromMetrics(registry=reg)

    metrics.record("article.title", "vi", "cache_hit")
    metrics.record("article.title", "vi", "cache_hit")
    metrics.record("article.title", "vi", "provider_call")
    metrics.record("article.title", "de", "cache_hit")
    metrics.record("scenario.title", "vi", "cache_hit")

    assert _counter_value(reg, "article.title", "vi", "cache_hit") == 2
    assert _counter_value(reg, "article.title", "vi", "provider_call") == 1
    assert _counter_value(reg, "article.title", "de", "cache_hit") == 1
    assert _counter_value(reg, "scenario.title", "vi", "cache_hit") == 1


def test_duplicate_construction_reuses_counter() -> None:
    # Two PromMetrics on the same registry must share the same
    # underlying Counter — otherwise prometheus_client raises.
    reg = CollectorRegistry()
    m1 = PromMetrics(registry=reg)
    m2 = PromMetrics(registry=reg)

    m1.record("article.title", "vi", "cache_hit")
    m2.record("article.title", "vi", "cache_hit")

    assert _counter_value(reg, "article.title", "vi", "cache_hit") == 2


def test_help_text_lists_all_source_values() -> None:
    reg = CollectorRegistry()
    metrics = PromMetrics(registry=reg)
    # Touch the counter so it shows up in collect()
    metrics.record("article.title", "vi", "cache_hit")

    for family in reg.collect():
        # family.name is COUNTER_NAME (bare). Sample names are
        # COUNTER_SAMPLE_NAME with the `_total` suffix.
        if family.name != COUNTER_NAME:
            continue
        help_text = family.documentation
        for required in (
            "english_passthrough",
            "override",
            "cache_hit",
            "cache_swr",
            "cache_miss_share",
            "provider_call",
            "provider_error",
        ):
            assert required in help_text, f"help text missing {required!r}"
        return
    pytest.fail(f"counter {COUNTER_NAME} not found in registry")


def test_seam_metrics_protocol_compat() -> None:
    # PromMetrics duck-types into the Metrics Protocol from seam.py.
    # We verify by calling through the Protocol-typed reference.
    from kielo_shared.localization.seam import Metrics

    reg = CollectorRegistry()
    m: Metrics = PromMetrics(registry=reg)
    m.record("article.title", "vi", "cache_hit")
    assert _counter_value(reg, "article.title", "vi", "cache_hit") == 1
