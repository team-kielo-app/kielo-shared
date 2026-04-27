"""Tests for kielo_shared.httpx_hooks."""
from __future__ import annotations

import httpx
import pytest

from kielo_shared.db_utils import set_active_language
from kielo_shared.httpx_hooks import (
    KIELO_LEARNING_LANGUAGE_HEADER,
    inject_active_language_header,
)


def _build_request(existing_headers: dict | None = None) -> httpx.Request:
    return httpx.Request(
        "GET",
        "https://svc.test/x",
        headers=existing_headers or {},
    )


@pytest.mark.asyncio
async def test_injects_when_contextvar_is_set():
    token = set_active_language("sv")
    try:
        request = _build_request()
        await inject_active_language_header(request)
        assert request.headers[KIELO_LEARNING_LANGUAGE_HEADER] == "sv"
    finally:
        from kielo_shared.db_utils import reset_active_language

        reset_active_language(token)


@pytest.mark.asyncio
async def test_noop_when_contextvar_is_unset():
    request = _build_request()
    await inject_active_language_header(request)
    assert KIELO_LEARNING_LANGUAGE_HEADER not in request.headers


@pytest.mark.asyncio
async def test_preserves_existing_header():
    # Per-call overrides — admin tooling that targets a specific language
    # must not be clobbered by the contextvar-derived value.
    token = set_active_language("sv")
    try:
        request = _build_request({KIELO_LEARNING_LANGUAGE_HEADER: "fi"})
        await inject_active_language_header(request)
        assert request.headers[KIELO_LEARNING_LANGUAGE_HEADER] == "fi"
    finally:
        from kielo_shared.db_utils import reset_active_language

        reset_active_language(token)
