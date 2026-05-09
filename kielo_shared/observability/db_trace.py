"""Stamp the active trace_id onto every SQL statement as a comment.

When `attach_query_trace(engine)` runs, every statement issued by that
SQLAlchemy engine gets a leading comment like:

    /* trace_id=abc123 request_id=20260509T141523-2f */ SELECT …

Postgres logs that comment alongside the query in `pg_stat_activity`,
slow-query logs, and `auto_explain` output. Joining a slow-query report
back to the originating HTTP request becomes a grep against the trace_id
the client reported.

Works with sync OR async SQLAlchemy engines — the listener attaches to
the underlying sync_engine when the async wrapper exposes it.

No-ops when the contextvar is empty (background workers without a
request scope) — keep the SQL byte-for-byte identical so plan caching is
not invalidated by stamping comments unnecessarily.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import event

from kielo_shared.trace import current_trace_context


logger = logging.getLogger(__name__)


def attach_query_trace(engine: Any) -> None:
    """Install a `before_cursor_execute` listener on `engine`.

    Idempotent — re-attaching is safe (the listener is bound by closure,
    so a second attach simply layers another comment which still parses).
    """
    target = getattr(engine, "sync_engine", engine)

    @event.listens_for(target, "before_cursor_execute", retval=True)
    def _stamp_trace_comment(  # noqa: D401, ANN001
        conn, cursor, statement, parameters, context, executemany  # noqa: ARG001
    ):
        try:
            tc = current_trace_context()
        except Exception:  # noqa: BLE001
            return statement, parameters
        if tc is None or tc.is_zero():
            return statement, parameters
        # Don't stamp twice if a prior layer already did. Cheap prefix check.
        if statement.startswith("/* trace_id="):
            return statement, parameters
        comment = (
            f"/* trace_id={tc.trace_id} "
            f"request_id={tc.request_id or ''} */ "
        )
        return comment + statement, parameters

    logger.info("attach_query_trace: installed on %s", target)


__all__ = ["attach_query_trace"]
