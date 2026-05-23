"""Tests for kielo_shared.observability.db_trace.attach_query_trace.

Uses a SQLite in-memory engine because we only need to validate that
the SQLAlchemy event hook fires + the statement-rewriting logic is
correct. Postgres-specific behavior (search_path, asyncpg dialect) is
out of scope for this test.
"""
from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import create_engine, text

from kielo_shared.observability import attach_query_trace
from kielo_shared.trace import (
    TraceContext,
    reset_current_trace_context,
    set_current_trace_context,
)


@pytest.fixture
def sqlite_engine():
    eng = create_engine("sqlite:///:memory:")
    yield eng
    eng.dispose()


def _install_capture_listener(engine: Any) -> list[str]:
    """Attach a before_cursor_execute listener AFTER attach_query_trace
    so the captured statement reflects the rewritten form. SQLAlchemy
    fires listeners in registration order; this helper is invoked from
    the test body, AFTER attach_query_trace runs."""
    captured: list[str] = []
    from sqlalchemy import event

    @event.listens_for(engine, "before_cursor_execute")
    def _capture(  # noqa: ANN001
        conn, cursor, statement, parameters, context, executemany,  # noqa: ARG001
    ):
        captured.append(statement)

    return captured


def test_stamps_trace_comment_when_context_is_set(sqlite_engine: Any):
    attach_query_trace(sqlite_engine)
    captured_statements = _install_capture_listener(sqlite_engine)

    tc = TraceContext(
        trace_id="abcdef0123456789abcdef0123456789",
        span_id="1122334455667788",
        request_id="20260523T120000-aa",
    )
    token = set_current_trace_context(tc)
    try:
        with sqlite_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    finally:
        reset_current_trace_context(token)

    assert len(captured_statements) >= 1
    rewritten = captured_statements[-1]
    assert rewritten.startswith("/* trace_id=abcdef0123456789abcdef0123456789 ")
    assert "request_id=20260523T120000-aa" in rewritten
    assert "SELECT 1" in rewritten


def test_noop_when_trace_context_is_zero(sqlite_engine: Any):
    """No-op preserves SQL bytes identically so the plan cache isn't
    invalidated by random comment stamping in background workers."""
    attach_query_trace(sqlite_engine)
    captured_statements = _install_capture_listener(sqlite_engine)

    # No set_current_trace_context call → contextvar carries default
    # zero TraceContext (is_zero() is True).
    with sqlite_engine.connect() as conn:
        conn.execute(text("SELECT 2"))

    assert len(captured_statements) >= 1
    assert captured_statements[-1].startswith("SELECT 2")
    assert "trace_id=" not in captured_statements[-1]


def test_does_not_double_stamp(sqlite_engine: Any):
    """Calling attach_query_trace twice (e.g. in a service that
    re-imports the engine for tests) must not produce nested comments."""
    attach_query_trace(sqlite_engine)
    attach_query_trace(sqlite_engine)
    captured_statements = _install_capture_listener(sqlite_engine)

    tc = TraceContext(
        trace_id="abcdef0123456789abcdef0123456789",
        span_id="1122334455667788",
        request_id="r",
    )
    token = set_current_trace_context(tc)
    try:
        with sqlite_engine.connect() as conn:
            conn.execute(text("SELECT 3"))
    finally:
        reset_current_trace_context(token)

    rewritten = captured_statements[-1]
    # The listener's own startswith("/* trace_id=") guard prevents
    # the second pass from prepending another comment.
    assert rewritten.count("/* trace_id=") == 1
