"""Kill-switch client: pure rule, 30s cache, last-good copy, fail-open."""

from __future__ import annotations

import httpx
import pytest

from kielo_shared import opswitch
from kielo_shared.opswitch import (
    KEY_KTV_FEED,
    KEY_LLM_GENERATION,
    SwitchClient,
    error_body,
    evaluate,
)

def _row(key, scope_type="global", scope_value="", enabled=False, message=None):
    return {
        "switch_key": key,
        "scope_type": scope_type,
        "scope_value": scope_value,
        "enabled": enabled,
        "message": message,
    }


def test_no_rows_reads_as_on():
    assert evaluate([], KEY_LLM_GENERATION).off is False


def test_enabled_row_is_on():
    assert evaluate([_row(KEY_LLM_GENERATION, enabled=True)], KEY_LLM_GENERATION).off is False


def test_global_off_uses_default_message():
    decision = evaluate([_row(KEY_LLM_GENERATION)], KEY_LLM_GENERATION)
    assert decision.off is True
    assert decision.message == opswitch.DEFAULT_MESSAGE
    assert decision.custom is False


def test_other_key_is_untouched():
    assert evaluate([_row(KEY_KTV_FEED)], KEY_LLM_GENERATION).off is False


def test_language_scope_only_matches_that_language():
    rows = [_row(KEY_LLM_GENERATION, "language", "sv")]
    assert evaluate(rows, KEY_LLM_GENERATION, language="sv").off is True
    assert evaluate(rows, KEY_LLM_GENERATION, language="SV ").off is True
    assert evaluate(rows, KEY_LLM_GENERATION, language="fi").off is False
    assert evaluate(rows, KEY_LLM_GENERATION).off is False


def test_platform_scope_only_matches_that_platform():
    rows = [_row(KEY_KTV_FEED, "platform", "ios")]
    assert evaluate(rows, KEY_KTV_FEED, platform="ios").off is True
    assert evaluate(rows, KEY_KTV_FEED, platform="android").off is False


def test_most_specific_off_row_supplies_the_message():
    rows = [
        _row(KEY_LLM_GENERATION, message="global"),
        _row(KEY_LLM_GENERATION, "platform", "ios", message="platform"),
        _row(KEY_LLM_GENERATION, "language", "fi", message="language"),
    ]
    decision = evaluate(rows, KEY_LLM_GENERATION, language="fi", platform="ios")
    assert (decision.message, decision.custom, decision.scope_type) == ("language", True, "language")
    decision = evaluate(rows, KEY_LLM_GENERATION, language="sv", platform="ios")
    assert decision.message == "platform"
    decision = evaluate(rows, KEY_LLM_GENERATION, language="sv", platform="web")
    assert decision.message == "global"


def test_blank_message_falls_back_to_default():
    decision = evaluate([_row(KEY_LLM_GENERATION, message="   ")], KEY_LLM_GENERATION)
    assert decision.message == opswitch.DEFAULT_MESSAGE
    assert decision.custom is False


def test_error_body_is_the_canonical_envelope():
    decision = evaluate([_row(KEY_LLM_GENERATION, message="Back soon")], KEY_LLM_GENERATION)
    body = error_body(KEY_LLM_GENERATION, decision)
    assert body["message"] == "Back soon"
    assert body["error"] == {
        "code": "FEATURE_DISABLED",
        "message": "Back soon",
        "details": {"switch_key": KEY_LLM_GENERATION, "custom_message": True},
    }


class _Store:
    """Stands in for httpx.AsyncClient against kielo-localization."""

    def __init__(self):
        self.calls = 0
        self.headers_seen = []
        self.status = 200
        self.body = {"items": []}
        self.error = None

    def client_factory(self):
        store = self

        class _Client:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, headers=None):
                store.calls += 1
                store.headers_seen.append((url, headers))
                if store.error:
                    raise store.error
                request = httpx.Request("GET", url)
                return httpx.Response(store.status, json=store.body, request=request)

        return _Client


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def store(monkeypatch):
    fake = _Store()
    monkeypatch.setattr(opswitch.httpx, "AsyncClient", fake.client_factory())
    return fake


@pytest.mark.asyncio
async def test_off_row_from_store_refuses(store):
    store.body = {"items": [_row(KEY_LLM_GENERATION, message="Paused")]}
    client = SwitchClient("http://loc/", "secret")
    decision = await client.check(KEY_LLM_GENERATION)
    assert decision.off is True and decision.message == "Paused"
    url, headers = store.headers_seen[0]
    assert url == "http://loc/internal/api/v3/localization/operator-switches"
    assert headers == {"X-Internal-API-Key": "secret"}


@pytest.mark.asyncio
async def test_enveloped_data_items_are_read(store):
    store.body = {"data": {"items": [_row(KEY_LLM_GENERATION)]}}
    assert (await SwitchClient("http://loc").check(KEY_LLM_GENERATION)).off is True


@pytest.mark.asyncio
async def test_checks_are_cached_until_ttl(store):
    clock = _Clock()
    client = SwitchClient("http://loc", ttl=30, clock=clock)
    await client.check(KEY_LLM_GENERATION)
    clock.now += 29
    await client.check(KEY_LLM_GENERATION)
    assert store.calls == 1
    clock.now += 2
    await client.check(KEY_LLM_GENERATION)
    assert store.calls == 2


@pytest.mark.asyncio
async def test_flip_is_seen_after_the_ttl(store):
    clock = _Clock()
    client = SwitchClient("http://loc", ttl=30, clock=clock)
    assert (await client.check(KEY_LLM_GENERATION)).off is False
    store.body = {"items": [_row(KEY_LLM_GENERATION)]}
    assert (await client.check(KEY_LLM_GENERATION)).off is False
    clock.now += 31
    assert (await client.check(KEY_LLM_GENERATION)).off is True


@pytest.mark.asyncio
async def test_store_down_with_no_copy_fails_open(store):
    store.error = httpx.ConnectError("refused")
    client = SwitchClient("http://loc")
    assert (await client.check(KEY_LLM_GENERATION)).off is False


@pytest.mark.asyncio
async def test_store_error_status_fails_open(store):
    store.status = 500
    store.body = {"items": [_row(KEY_LLM_GENERATION)]}
    assert (await SwitchClient("http://loc").check(KEY_LLM_GENERATION)).off is False


@pytest.mark.asyncio
async def test_store_down_keeps_the_last_good_copy(store):
    clock = _Clock()
    store.body = {"items": [_row(KEY_LLM_GENERATION)]}
    client = SwitchClient("http://loc", ttl=30, clock=clock)
    assert (await client.check(KEY_LLM_GENERATION)).off is True
    store.error = httpx.ConnectError("refused")
    clock.now += 31
    assert (await client.check(KEY_LLM_GENERATION)).off is True


@pytest.mark.asyncio
async def test_outage_costs_one_fetch_per_ttl(store):
    clock = _Clock()
    store.error = httpx.ConnectError("refused")
    client = SwitchClient("http://loc", ttl=30, clock=clock)
    for _ in range(5):
        await client.check(KEY_LLM_GENERATION)
    assert store.calls == 1


@pytest.mark.asyncio
async def test_unset_base_url_is_always_on(store):
    assert (await SwitchClient("").check(KEY_LLM_GENERATION)).off is False
    assert store.calls == 0
