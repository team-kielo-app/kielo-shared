"""Tests for kielo_shared.httpx_hooks."""
from __future__ import annotations

import httpx
import pytest

from kielo_shared.db_utils import (
    reset_active_support_language,
    set_active_language,
    set_active_support_language,
)
from kielo_shared.httpx_hooks import (
    LEARNING_LANGUAGE_HEADER,
    LEARNING_LANGUAGE_QUERY_PARAM,
    SUPPORT_LANGUAGE_HEADER,
    SUPPORT_LANGUAGE_QUERY_PARAM,
    inject_active_language_query,
    inject_active_support_language_query,
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


# ---------------------------------------------------------------------------
# Sweep SSSS-C: support-language hook regression tests.
# Sibling shape to the learning-language tests above. Pins:
#   1. Stamps both query param + header from contextvar.
#   2. No-op when contextvar empty (background workers, CLI tools).
#   3. Caller-set explicit query param survives (admin tooling override).
#   4. Caller-set explicit header survives (admin tooling override).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_support_lang_injects_query_and_header_when_contextvar_set():
    token = set_active_support_language("vi")
    try:
        request = _build_request()
        await inject_active_support_language_query(request)
        assert request.url.params[SUPPORT_LANGUAGE_QUERY_PARAM] == "vi"
        assert request.headers[SUPPORT_LANGUAGE_HEADER] == "vi"
    finally:
        reset_active_support_language(token)


@pytest.mark.asyncio
async def test_support_lang_noop_when_contextvar_unset():
    request = _build_request()
    await inject_active_support_language_query(request)
    assert SUPPORT_LANGUAGE_QUERY_PARAM not in request.url.params
    assert SUPPORT_LANGUAGE_HEADER not in request.headers


@pytest.mark.asyncio
async def test_support_lang_preserves_existing_query_param():
    token = set_active_support_language("vi")
    try:
        request = _build_request({SUPPORT_LANGUAGE_QUERY_PARAM: "sv"})
        await inject_active_support_language_query(request)
        # Caller override survives; ctx value does not clobber.
        assert request.url.params[SUPPORT_LANGUAGE_QUERY_PARAM] == "sv"
    finally:
        reset_active_support_language(token)


@pytest.mark.asyncio
async def test_support_lang_preserves_existing_header():
    token = set_active_support_language("vi")
    try:
        request = httpx.Request(
            "GET",
            "https://svc.test/x",
            headers={SUPPORT_LANGUAGE_HEADER: "sv"},
        )
        await inject_active_support_language_query(request)
        assert request.headers[SUPPORT_LANGUAGE_HEADER] == "sv"
    finally:
        reset_active_support_language(token)


@pytest.mark.asyncio
async def test_support_lang_and_learning_lang_independent():
    """The two hooks read independent contextvars and don't interfere."""
    learning_token = set_active_language("fi")
    support_token = set_active_support_language("vi")
    try:
        request = _build_request()
        await inject_active_language_query(request)
        await inject_active_support_language_query(request)
        # Learning language → fi; support → vi. Both stamped via both channels.
        assert request.url.params[LEARNING_LANGUAGE_QUERY_PARAM] == "fi"
        assert request.headers[LEARNING_LANGUAGE_HEADER] == "fi"
        assert request.url.params[SUPPORT_LANGUAGE_QUERY_PARAM] == "vi"
        assert request.headers[SUPPORT_LANGUAGE_HEADER] == "vi"
    finally:
        reset_active_support_language(support_token)
        from kielo_shared.db_utils import reset_active_language

        reset_active_language(learning_token)
