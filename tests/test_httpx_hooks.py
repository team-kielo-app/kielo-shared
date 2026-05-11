"""Tests for kielo_shared.httpx_hooks."""
from __future__ import annotations

import httpx
import pytest

from kielo_shared.db_utils import set_active_language
from kielo_shared.httpx_hooks import (
    LEARNING_LANGUAGE_QUERY_PARAM,
    inject_active_language_query,
)


def _build_request(existing_params: dict | None = None) -> httpx.Request:
    return httpx.Request(
        "GET",
        "https://svc.test/x",
        params=existing_params or {},
    )


@pytest.mark.asyncio
async def test_injects_when_contextvar_is_set():
    token = set_active_language("sv")
    try:
        request = _build_request()
        await inject_active_language_query(request)
        assert request.url.params[LEARNING_LANGUAGE_QUERY_PARAM] == "sv"
    finally:
        from kielo_shared.db_utils import reset_active_language

        reset_active_language(token)


@pytest.mark.asyncio
async def test_noop_when_contextvar_is_unset():
    request = _build_request()
    await inject_active_language_query(request)
    assert LEARNING_LANGUAGE_QUERY_PARAM not in request.url.params


@pytest.mark.asyncio
async def test_preserves_existing_param():
    token = set_active_language("sv")
    try:
        request = _build_request({LEARNING_LANGUAGE_QUERY_PARAM: "fi"})
        await inject_active_language_query(request)
        assert request.url.params[LEARNING_LANGUAGE_QUERY_PARAM] == "fi"
    finally:
        from kielo_shared.db_utils import reset_active_language

        reset_active_language(token)
