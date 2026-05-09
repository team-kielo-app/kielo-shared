"""Prometheus emitters for seam telemetry.

Three record shapes covered:
  * llm_call       — one per LLM provider invocation
  * localization_batch — one per translation batch
  * prewarm_*      — session-localization prewarm lifecycle

Each emitter:
  1. Always logs the record (preserves existing log-based queries).
  2. If `prometheus_client` is importable, increments labelled counters
     and observes labelled histograms — `/metrics` scrape returns them.

Histogram buckets cover the realistic latency range: 50ms baseline up to
~30s for cold LLM calls. Cardinality controls:
  * `task` label is the seam's task tag (~10-20 values, stable).
  * `provider` label is the version-stamped provider id.
  * `cached` is a boolean string for partitioning hit-rate dashboards.
  * `error` is the exception class name OR empty — bounded by raise sites.

Resist the urge to add free-form labels; high-cardinality (e.g. user_id,
item_id) belongs in trace logs, not metrics.
"""
from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


try:
    from prometheus_client import REGISTRY, Counter, Histogram, generate_latest
    from prometheus_client import CollectorRegistry  # noqa: F401 — re-exported via REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


# Histogram bucket profile for LLM-style latencies (ms → seconds).
_LATENCY_BUCKETS_S = (
    0.005,  # cache hit
    0.025,
    0.050,
    0.100,
    0.250,
    0.500,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)


# Buckets for char-count distributions (inputs/outputs). LLM payloads
# rarely exceed 8 KiB; provide enough resolution at low end.
_CHAR_BUCKETS = (50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000)


# ─────────────────────────── prometheus metrics ──────────────────────────


if PROMETHEUS_AVAILABLE:
    LLM_CALLS_TOTAL = Counter(
        "kielo_llm_calls_total",
        "LLM call count by provider/task/cache state.",
        labelnames=("provider", "task", "cache_policy", "cached", "error"),
    )
    LLM_LATENCY_S = Histogram(
        "kielo_llm_latency_seconds",
        "LLM call latency in seconds.",
        labelnames=("provider", "task", "cached"),
        buckets=_LATENCY_BUCKETS_S,
    )
    LLM_CHAR_IN = Histogram(
        "kielo_llm_char_count_in",
        "LLM prompt char count distribution.",
        labelnames=("provider", "task"),
        buckets=_CHAR_BUCKETS,
    )
    LLM_CHAR_OUT = Histogram(
        "kielo_llm_char_count_out",
        "LLM response char count distribution.",
        labelnames=("provider", "task"),
        buckets=_CHAR_BUCKETS,
    )

    LOC_BATCHES_TOTAL = Counter(
        "kielo_localization_batches_total",
        "Translation batch count by provider/locale-pair/error.",
        labelnames=("provider", "source_locale", "target_locale", "error"),
    )
    LOC_BATCH_LATENCY_S = Histogram(
        "kielo_localization_batch_latency_seconds",
        "Translation batch wall-clock in seconds.",
        labelnames=("provider", "target_locale"),
        buckets=_LATENCY_BUCKETS_S,
    )
    LOC_BATCH_ITEMS = Histogram(
        "kielo_localization_batch_items",
        "Items per translation batch.",
        labelnames=("provider", "target_locale"),
        buckets=(1, 5, 10, 25, 50, 100, 250),
    )
    LOC_BATCH_CHARS = Histogram(
        "kielo_localization_batch_chars",
        "Total source-text chars per translation batch.",
        labelnames=("provider", "target_locale"),
        buckets=_CHAR_BUCKETS,
    )

    PREWARM_TOTAL = Counter(
        "kielo_session_prewarm_total",
        "Session-localization prewarm outcomes.",
        labelnames=("stage", "result"),
    )


# ────────────────────────────── emitters ─────────────────────────────────


def llm_emit(record: dict[str, Any]) -> None:
    """Emit one `llm_call` record. Safe with or without prometheus_client."""
    logger.info("llm_call %s", record)
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        provider = str(record.get("provider") or "unknown")
        task = str(record.get("task") or "generic")
        cache_policy = str(record.get("cache_policy") or "none")
        cached = "true" if record.get("cached") else "false"
        error = str(record.get("error") or "")
        LLM_CALLS_TOTAL.labels(
            provider=provider,
            task=task,
            cache_policy=cache_policy,
            cached=cached,
            error=error,
        ).inc()
        latency_ms = float(record.get("latency_ms") or 0)
        LLM_LATENCY_S.labels(
            provider=provider, task=task, cached=cached
        ).observe(latency_ms / 1000.0)
        LLM_CHAR_IN.labels(provider=provider, task=task).observe(
            float(record.get("char_count_in") or 0)
        )
        LLM_CHAR_OUT.labels(provider=provider, task=task).observe(
            float(record.get("char_count_out") or 0)
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("llm_emit prometheus fanout failed: %s", exc)


def localization_emit(record: dict[str, Any]) -> None:
    """Emit one `localization_batch` record."""
    logger.info("localization_batch %s", record)
    if not PROMETHEUS_AVAILABLE:
        return
    try:
        provider = str(record.get("provider") or "unknown")
        source = str(record.get("source_locale") or "")
        target = str(record.get("target_locale") or "")
        error = str(record.get("error") or "")
        LOC_BATCHES_TOTAL.labels(
            provider=provider,
            source_locale=source,
            target_locale=target,
            error=error,
        ).inc()
        latency_ms = float(record.get("latency_ms") or 0)
        LOC_BATCH_LATENCY_S.labels(
            provider=provider, target_locale=target
        ).observe(latency_ms / 1000.0)
        LOC_BATCH_ITEMS.labels(
            provider=provider, target_locale=target
        ).observe(float(record.get("item_count") or 0))
        LOC_BATCH_CHARS.labels(
            provider=provider, target_locale=target
        ).observe(float(record.get("char_count") or 0))
    except Exception as exc:  # noqa: BLE001
        logger.debug("localization_emit prometheus fanout failed: %s", exc)


def prewarm_emit(*, stage: str, result: str) -> None:
    """Increment a labelled counter for a prewarm outcome.

    Phase E records emit unstructured text; this helper exists so
    prewarm sites can emit BOTH log + metric in one call. Migration is
    optional — log-only still produces the same `prewarm_*` lines.
    """
    logger.info("prewarm_metric stage=%s result=%s", stage, result)
    if PROMETHEUS_AVAILABLE:
        try:
            PREWARM_TOTAL.labels(stage=stage, result=result).inc()
        except Exception as exc:  # noqa: BLE001
            logger.debug("prewarm_emit prometheus fanout failed: %s", exc)


# ─────────────────────────── /metrics text ───────────────────────────────


def metrics_text() -> bytes:
    """Render the default registry to Prometheus text format. Returns
    empty bytes when prometheus_client isn't available so the `/metrics`
    handler stays trivial."""
    if not PROMETHEUS_AVAILABLE:
        return b""
    return generate_latest(REGISTRY)


__all__ = [
    "PROMETHEUS_AVAILABLE",
    "llm_emit",
    "localization_emit",
    "metrics_text",
    "prewarm_emit",
]
