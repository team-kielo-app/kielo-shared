"""Tests for kielo_shared.http (internal_headers + internal_client_*)."""
from __future__ import annotations

import httpx
import pytest

from kielo_shared.http import (
    INTERNAL_API_KEY_HEADER,
    internal_client_async,
    internal_headers,
)
from kielo_shared.trace import (
    TraceContext,
    set_current_trace_context,
    reset_current_trace_context,
)


def test_internal_headers_with_key():
    headers = internal_headers(api_key="s3cret")
    assert headers[INTERNAL_API_KEY_HEADER] == "s3cret"


def test_internal_headers_no_key_no_trace_returns_empty():
    headers = internal_headers()
    assert headers == {}


def test_internal_headers_includes_trace_when_context_active():
    tc = TraceContext(
        trace_id="a" * 32,
        span_id="b" * 16,
        request_id="req-123",
    )
    token = set_current_trace_context(tc)
    try:
        headers = internal_headers(api_key="key")
    finally:
        reset_current_trace_context(token)

    assert headers[INTERNAL_API_KEY_HEADER] == "key"
    assert "Traceparent" in headers
    assert headers["Traceparent"].startswith("00-" + "a" * 32 + "-" + "b" * 16)
    assert headers["X-Request-Id"] == "req-123"
    assert headers["X-Client-Trace-Id"] == "a" * 32


def test_internal_headers_extra_overrides():
    headers = internal_headers(
        api_key="key",
        extra={"Content-Type": "application/json", INTERNAL_API_KEY_HEADER: "override"},
    )
    assert headers["Content-Type"] == "application/json"
    assert headers[INTERNAL_API_KEY_HEADER] == "override"


@pytest.mark.asyncio
async def test_internal_client_async_sets_default_api_key_header():
    captured: dict[str, str] = {}

    async def transport_handler(request: httpx.Request) -> httpx.Response:
        for k, v in request.headers.items():
            captured[k.lower()] = v
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(transport_handler)
    async with internal_client_async(
        api_key="abc",
        transport=transport,
        base_url="https://svc.test",
    ) as client:
        resp = await client.get("/ping")
        assert resp.status_code == 200

    assert captured.get(INTERNAL_API_KEY_HEADER.lower()) == "abc"


@pytest.mark.asyncio
async def test_internal_client_async_stamps_trace_via_hook():
    captured: dict[str, str] = {}

    async def transport_handler(request: httpx.Request) -> httpx.Response:
        for k, v in request.headers.items():
            captured[k.lower()] = v
        return httpx.Response(200)

    transport = httpx.MockTransport(transport_handler)

    tc = TraceContext(
        trace_id="f" * 32,
        span_id="e" * 16,
        request_id="trace-rq",
    )
    token = set_current_trace_context(tc)
    try:
        async with internal_client_async(
            api_key="k",
            transport=transport,
            base_url="https://svc.test",
        ) as client:
            await client.get("/x")
    finally:
        reset_current_trace_context(token)

    # Hook should have stamped traceparent + x-client-trace-id.
    assert "traceparent" in captured
    assert captured["traceparent"].startswith("00-" + "f" * 32)
