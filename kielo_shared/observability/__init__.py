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

from kielo_shared.observability.db_trace import attach_query_trace
from kielo_shared.observability.metrics import (
    PROMETHEUS_AVAILABLE,
    llm_emit,
    localization_emit,
    metrics_text,
    prewarm_emit,
)

__all__ = [
    "PROMETHEUS_AVAILABLE",
    "attach_query_trace",
    "llm_emit",
    "localization_emit",
    "metrics_text",
    "prewarm_emit",
]
