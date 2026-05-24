"""kielo_shared.observability — metric exporters for the seam telemetry.

Wraps the structured records that `kielo_shared.llm` and
`kielo_shared.localization` decorators already emit. When `prometheus_client`
is installed, the exporters increment counters / observe histograms.
Without it, they fall back to log-only emission so the package is safe to
import everywhere.

Wire shape:

    from kielo_shared.observability import llm_emit
    from kielo_shared.llm import LLMMetricsDecorator

    LLMMetricsDecorator(inner_provider, emit=llm_emit)

The exporter's labels match the record-shape contracts documented in
`docs/architecture/llm_telemetry.md`. Bumping a label name is a breaking
change for downstream dashboards — coordinate before merging.
"""
from __future__ import annotations

from kielo_shared.observability.background_tasks import (
    spawn_background_task,
    spawn_background_task_lazy,
)
from kielo_shared.observability.db_trace import attach_query_trace
from kielo_shared.observability.metrics import (
    PROMETHEUS_AVAILABLE,
    idempotency_emit,
    legacy_alias_hit_emit,
    llm_emit,
    llm_generate_validate_emit,
    localization_emit,
    metrics_text,
    per_language_search_path_fallback_emit,
    prewarm_emit,
    pubsub_ack_emit,
    pubsub_publish_emit,
    side_effect_failed_emit,
    tts_cache_emit,
    v1_route_hit_emit,
)

__all__ = [
    "PROMETHEUS_AVAILABLE",
    "attach_query_trace",
    "idempotency_emit",
    "legacy_alias_hit_emit",
    "llm_emit",
    "llm_generate_validate_emit",
    "localization_emit",
    "metrics_text",
    "per_language_search_path_fallback_emit",
    "prewarm_emit",
    "pubsub_ack_emit",
    "pubsub_publish_emit",
    "side_effect_failed_emit",
    "spawn_background_task",
    "spawn_background_task_lazy",
    "tts_cache_emit",
    "v1_route_hit_emit",
]
