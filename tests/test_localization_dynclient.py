"""Unit tests for kielo_shared.localization.dynclient. Uses
httpx.MockTransport so no real network or kielo-localization
deployment is required.
"""

from __future__ import annotations

import json

import httpx
import pytest

from kielo_shared.localization.dynclient import (
    DynamicTranslation,
    DynClient,
    DynClientError,
    FetchRequest,
    FetchResponse,
    UpsertRequest,
    UpsertResponse,
)


def _make_client(handler) -> DynClient:
    """Build a DynClient wired to an httpx.AsyncClient with a
    MockTransport so no real HTTP traffic is issued.
    """
    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(transport=transport, base_url="http://kielo-localization")
    return DynClient(
        base_url="http://kielo-localization",
        api_key="test-key",
        client=async_client,
    )


@pytest.mark.asyncio
async def test_upsert_posts_payload_and_returns_response():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = request.url
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "row": {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "resource_type": captured["body"]["resource_type"],
                    "resource_id": captured["body"]["resource_id"],
                    "source_version": captured["body"]["source_version"],
                    "language_code": captured["body"]["language_code"],
                    "translated_text": captured["body"]["translated_text"],
                    "status": "machine",
                    "created_at": "2026-05-19T00:00:00Z",
                    "updated_at": "2026-05-19T00:00:00Z",
                },
                "inserted": True,
            },
        )

    client = _make_client(handler)
    try:
        resp = await client.upsert(
            UpsertRequest(
                resource_type="article.paragraph",
                resource_id="22222222-2222-2222-2222-222222222222",
                source_version="abc",
                language_code="vi",
                translated_text="Một đoạn",
                source_locale="en",
                translator_source="lazy_translation",
            )
        )
    finally:
        await client.aclose()

    assert isinstance(resp, UpsertResponse)
    assert resp.inserted is True
    assert resp.row is not None
    assert resp.row.translated_text == "Một đoạn"

    assert captured["url"].path == "/internal/api/v3/localization/dynamic"
    assert captured["body"]["resource_type"] == "article.paragraph"
    assert captured["body"]["language_code"] == "vi"
    # Optional fields with values get serialized; unset ones don't.
    assert captured["body"]["source_locale"] == "en"
    assert captured["body"]["translator_source"] == "lazy_translation"
    assert "reviewer_id" not in captured["body"], "blank reviewer_id should be omitted"


@pytest.mark.asyncio
async def test_upsert_omits_optional_blank_fields():
    captured_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(
            201,
            json={"row": None, "inserted": True},
        )

    client = _make_client(handler)
    try:
        await client.upsert(
            UpsertRequest(
                resource_type="article.paragraph",
                resource_id="x",
                source_version="v",
                language_code="vi",
                translated_text="t",
                # status, source_locale, translator_source all blank
            )
        )
    finally:
        await client.aclose()

    # Required fields present.
    assert captured_body["resource_type"] == "article.paragraph"
    # Optional blanks dropped.
    assert "status" not in captured_body
    assert "source_locale" not in captured_body
    assert "translator_source" not in captured_body


@pytest.mark.asyncio
async def test_upsert_non2xx_raises_dynclienterror():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='{"message":"resource_type is required"}')

    client = _make_client(handler)
    try:
        with pytest.raises(DynClientError) as exc_info:
            await client.upsert(
                UpsertRequest(
                    resource_type="",
                    resource_id="x",
                    source_version="v",
                    language_code="vi",
                    translated_text="t",
                )
            )
    finally:
        await client.aclose()

    assert exc_info.value.status == 400
    assert "resource_type is required" in str(exc_info.value)


@pytest.mark.asyncio
async def test_fetch_by_resources_returns_items():
    captured_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "resource_type": "article.paragraph",
                        "resource_id": captured_body["resource_ids"][0],
                        "source_version": "abc",
                        "language_code": "vi",
                        "translated_text": "Một đoạn",
                        "status": "machine",
                    }
                ]
            },
        )

    client = _make_client(handler)
    try:
        resp = await client.fetch_by_resources(
            FetchRequest(
                resource_types=["article.paragraph"],
                resource_ids=["44444444-4444-4444-4444-444444444444"],
                language_code="vi",
            )
        )
    finally:
        await client.aclose()

    assert isinstance(resp, FetchResponse)
    assert len(resp.items) == 1
    assert resp.items[0].translated_text == "Một đoạn"

    assert captured_body["resource_types"] == ["article.paragraph"]
    assert captured_body["language_code"] == "vi"
    # resource_id_prefix omitted when blank.
    assert "resource_id_prefix" not in captured_body


@pytest.mark.asyncio
async def test_fetch_by_resources_uses_prefix_path():
    captured_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(200, json={"items": []})

    client = _make_client(handler)
    try:
        await client.fetch_by_resources(
            FetchRequest(
                resource_types=["kielotv.caption.cue"],
                resource_id_prefix="abc.",
                language_code="fi",
            )
        )
    finally:
        await client.aclose()

    assert captured_body["resource_id_prefix"] == "abc."
    assert "resource_ids" not in captured_body


@pytest.mark.asyncio
async def test_fetch_by_resources_handles_empty_items():
    """An empty result list is normal (no rows match the filter)
    and should NOT raise — just return an empty FetchResponse.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": []})

    client = _make_client(handler)
    try:
        resp = await client.fetch_by_resources(
            FetchRequest(
                resource_types=["article.paragraph"],
                resource_ids=["55555555-5555-5555-5555-555555555555"],
            )
        )
    finally:
        await client.aclose()

    assert resp.items == []


@pytest.mark.asyncio
async def test_fetch_non2xx_raises_dynclienterror():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='{"message":"resource_ids required"}')

    client = _make_client(handler)
    try:
        with pytest.raises(DynClientError) as exc_info:
            await client.fetch_by_resources(
                FetchRequest(resource_types=["article.paragraph"])
            )
    finally:
        await client.aclose()

    assert exc_info.value.status == 400


def test_dynamic_translation_from_payload_with_minimal_fields():
    dt = DynamicTranslation.from_payload(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "resource_type": "article.paragraph",
            "resource_id": "x",
            "source_version": "v",
            "language_code": "vi",
            "translated_text": "t",
        }
    )
    assert dt.id == "11111111-1111-1111-1111-111111111111"
    assert dt.translated_text == "t"
    assert dt.source_locale is None
    assert dt.translator_source is None


# ============================================================================
# Sweep WWWW: upsert_bulk tests
# ============================================================================


@pytest.mark.asyncio
async def test_upsert_bulk_posts_list_and_returns_results():
    captured: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        # Mirror the items back with synthesized IDs + alternating inserted flag.
        results = []
        for i, item in enumerate(captured["body"]["items"]):
            results.append(
                {
                    "row": {
                        "id": f"00000000-0000-0000-0000-00000000000{i}",
                        "resource_type": item["resource_type"],
                        "resource_id": item["resource_id"],
                        "source_version": item["source_version"],
                        "language_code": item["language_code"],
                        "translated_text": item["translated_text"],
                        "status": item.get("status", "machine"),
                        "source_locale": None,
                        "translator_source": None,
                        "reviewed_by": None,
                        "reviewed_at": None,
                        "created_at": "2026-06-01T10:00:00Z",
                        "updated_at": "2026-06-01T10:00:00Z",
                    },
                    "inserted": i % 2 == 0,
                }
            )
        return httpx.Response(200, json={"results": results})

    client = _make_client(handler)
    inputs = [
        UpsertRequest(
            resource_type="lesson",
            resource_id=f"l{i}",
            source_version="v1",
            language_code="vi",
            translated_text=f"Bài học {i}",
        )
        for i in range(5)
    ]
    out = await client.upsert_bulk(inputs)
    assert captured["url"].endswith("/internal/api/v3/localization/dynamic/bulk")
    assert len(captured["body"]["items"]) == 5
    assert len(out) == 5
    for i, r in enumerate(out):
        assert r.inserted == (i % 2 == 0)
        assert r.row.translated_text == f"Bài học {i}"


@pytest.mark.asyncio
async def test_upsert_bulk_empty_does_not_post():
    called = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called += 1
        return httpx.Response(200, json={"results": []})

    client = _make_client(handler)
    out = await client.upsert_bulk([])
    assert out == []
    assert called == 0, "empty batch should skip the HTTP call entirely"


@pytest.mark.asyncio
async def test_upsert_bulk_non2xx_raises():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = _make_client(handler)
    with pytest.raises(DynClientError):
        await client.upsert_bulk(
            [
                UpsertRequest(
                    resource_type="x",
                    resource_id="x",
                    source_version="v",
                    language_code="vi",
                    translated_text="t",
                )
            ]
        )
