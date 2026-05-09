"""Unified trace-aware logging filter for every Python Kielo service.

Attach this filter to a stdlib logging handler so the formatter can
render ``%(trace_id)s``, ``%(span_id)s``, ``%(parent_span_id)s`` and
``%(request_id)s``. Without the filter those fields raise ``KeyError``
during formatting; with it they fall back to ``"-"`` when no trace is
active (module-load logs, CLI tooling outside a request scope).

Why this lives here
-------------------
kielolearn-engine, kielo-ingest-processor and kielo-web-ingest used to
each carry their own near-identical filter. They drifted (the
web-ingest worker had no filter at all, so its logs couldn't be
correlated with the CMS / ingest-processor lines they produced via
HTTP fan-out and Pub/Sub). Moving the filter here pins the contract:
every Python service reads the same contextvar (``kielo_shared.trace``)
and emits the same record fields, so a single ``grep trace=<id>``
across all docker logs walks the whole trace.

Usage
-----

    import logging
    from kielo_shared.logging_filter import TraceLoggingFilter

    logging.basicConfig(
        format=(
            "%(asctime)s - %(name)s - %(levelname)s - "
            "[trace=%(trace_id)s req=%(request_id)s] %(message)s"
        ),
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(TraceLoggingFilter())
"""
from __future__ import annotations

import logging

from kielo_shared.trace import current_trace_context


class TraceLoggingFilter(logging.Filter):
    """Adds trace_id, span_id, parent_span_id, request_id to every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        tc = current_trace_context()
        record.trace_id = tc.trace_id or "-"
        record.span_id = tc.span_id or "-"
        record.parent_span_id = tc.parent_span_id or "-"
        record.request_id = tc.request_id or "-"
        return True


__all__ = ["TraceLoggingFilter"]
