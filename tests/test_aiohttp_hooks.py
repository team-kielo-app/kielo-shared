"""Tests for kielo_shared.aiohttp_hooks.

aiohttp is an optional dependency of kielo-shared (only kielo-web-ingest
uses it). When aiohttp is not installed these tests are skipped.
"""
from __future__ import annotations

import pytest

aiohttp = pytest.importorskip("aiohttp")

from aiohttp import web

from kielo_shared.aiohttp_hooks import internal_session, tracing_trace_config
from kielo_shared.db_utils import reset_active_language, set_active_language
from kielo_shared.http import INTERNAL_API_KEY_HEADER
from kielo_shared.trace import (
    TraceContext,
    reset_current_trace_context,
    set_current_trace_context,
)


@pytest.mark.asyncio
async def test_aiohttp_hook_stamps_trace_and_language_headers(aiohttp_server):
    captured: dict[str, str] = {}

    async def handler(request: web.Request) -> web.Response:
        for k, v in request.headers.items():
            captured[k.lower()] = v
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/ping", handler)
    server = await aiohttp_server(app)

    tc = TraceContext(
        trace_id="d" * 32,
        span_id="c" * 16,
        request_id="rq-aio",
    )
    token = set_current_trace_context(tc)
    lang_token = set_active_language("sv")
    try:
        async with aiohttp.ClientSession(
            trace_configs=[tracing_trace_config()]
        ) as session:
            async with session.get(str(server.make_url("/ping"))) as resp:
                assert resp.status == 200
    finally:
        reset_current_trace_context(token)
        reset_active_language(lang_token)

    assert "traceparent" in captured
    assert captured["traceparent"].startswith("00-" + "d" * 32)
    assert captured["x-request-id"] == "rq-aio"
    # aiohttp hook stamps the language as the canonical header
    # (URL params can't be mutated through TraceConfig — see hook docstring).
    assert captured["x-kielo-learning-language"] == "sv"


@pytest.mark.asyncio
async def test_internal_session_stamps_api_key(aiohttp_server):
    captured: dict[str, str] = {}

    async def handler(request: web.Request) -> web.Response:
        for k, v in request.headers.items():
            captured[k.lower()] = v
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/x", handler)
    server = await aiohttp_server(app)

    async with internal_session(api_key="aio-key") as session:
        async with session.get(str(server.make_url("/x"))) as resp:
            assert resp.status == 200

    assert captured.get(INTERNAL_API_KEY_HEADER.lower()) == "aio-key"


@pytest.mark.asyncio
async def test_aiohttp_hook_does_not_override_existing_language_header(
    aiohttp_server,
):
    captured: dict[str, str] = {}

    async def handler(request: web.Request) -> web.Response:
        for k, v in request.headers.items():
            captured[k.lower()] = v
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/x", handler)
    server = await aiohttp_server(app)

    lang_token = set_active_language("sv")
    try:
        async with aiohttp.ClientSession(
            trace_configs=[tracing_trace_config()]
        ) as session:
            async with session.get(
                str(server.make_url("/x")),
                headers={"X-Kielo-Learning-Language": "fi"},
            ) as resp:
                assert resp.status == 200
    finally:
        reset_active_language(lang_token)

    # explicit "fi" must win over contextvar "sv"
    assert captured["x-kielo-learning-language"] == "fi"
