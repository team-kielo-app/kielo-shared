"""Unit tests for kielo_shared.content_bridge.client deserialization.

The HTTP transport is not exercised here — we test the wire-shape
parser against synthetic payloads matching the Go server's response.

Post-Arc-1-audit (2026-06-07) the wire shape changed substantially:

- surface_entry_id REQUIRED (no fallback to surface_id).
- inflected_form_details (string) → morphology (dict) +
  inflected_form_details_raw (string).
- token_count surfaced.
- surface_title surfaced.
- start_word_index surfaced (nullable).
- position dropped.

These tests pin the new shape end-to-end + assert the strict
validation paths surface ValueError as the operator-ratified
"loud failure" discipline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from kielo_shared.content_bridge import (
    SURFACE_ARTICLE,
    SURFACE_EXERCISE_PROMPT,
    SURFACE_SCENARIO,
    SURFACE_VIDEO_CAPTION,
    SurfacesPage,
)
from kielo_shared.content_bridge.client import (
    BatchLookupResult,
    CountsBySurface,
    Morphology,
    SurfaceReference,
    _deserialize_batch_lookup,
    _deserialize_morphology,
    _deserialize_page,
    _deserialize_reference,
    _parse_iso8601,
)


def _article_payload(**overrides):
    """Helper: produce a canonical article reference payload.
    Overrides merge on top, so tests can mutate specific fields
    without re-typing the full shape every time.
    """
    surface_id = overrides.pop("surface_id", uuid4())
    surface_entry_id = overrides.pop("surface_entry_id", uuid4())
    base = {
        "surface_type": "article",
        "surface_id": str(surface_id),
        "surface_entry_id": str(surface_entry_id),
        "surface_title": "Bridge Test Article",
        "snippet_text": "Hän on hyvä ystävä.",
        "original_token_phrase": "ystävä",
        "token_count": 1,
        "morphology": {
            "case": "nominative",
            "number": "singular",
            "tense": None,
            "mood": None,
            "person": None,
            "voice": None,
            "clitics": [],
        },
        "inflected_form_details_raw": '{"case":"nominative","number":"singular"}',
        "language_code": "fi",
        "published_at": "2026-05-12T10:43:00Z",
        "start_word_index": 3,
        "paragraph_id": str(uuid4()),
    }
    base.update(overrides)
    return base


def test_deserialize_article_reference_full_shape():
    """Article references carry every Arc 1 post-audit field."""
    surface_id = uuid4()
    surface_entry_id = uuid4()
    paragraph_id = uuid4()
    raw = _article_payload(
        surface_id=surface_id,
        surface_entry_id=surface_entry_id,
        paragraph_id=str(paragraph_id),
    )

    ref = _deserialize_reference(raw)

    assert isinstance(ref, SurfaceReference)
    assert ref.surface_type == SURFACE_ARTICLE
    assert ref.surface_id == surface_id
    assert ref.surface_entry_id == surface_entry_id
    assert ref.surface_title == "Bridge Test Article"
    assert ref.snippet_text == "Hän on hyvä ystävä."
    assert ref.original_token_phrase == "ystävä"
    assert ref.token_count == 1
    assert ref.morphology.case == "nominative"
    assert ref.morphology.number == "singular"
    assert ref.morphology.tense is None
    assert ref.inflected_form_details_raw == '{"case":"nominative","number":"singular"}'
    assert ref.language_code == "fi"
    assert ref.paragraph_id == paragraph_id
    assert ref.start_word_index == 3
    assert ref.caption_index is None
    assert ref.timestamp_start_seconds is None
    assert ref.turn_index is None
    assert ref.prompt_segment_index is None


def test_deserialize_reference_rejects_missing_surface_entry_id():
    """Arc 1 audit hardening: surface_entry_id is REQUIRED. The
    pre-audit client fell back to surface_id silently, which would
    route notification deep links to the wrong URL the moment a
    future server forgot to emit the field. Now: raise loudly.
    """
    raw = _article_payload()
    raw.pop("surface_entry_id")

    with pytest.raises(ValueError, match="surface_entry_id"):
        _deserialize_reference(raw)


def test_deserialize_reference_rejects_unknown_surface_type():
    """Sweep D casing-drift class: wire→typed casts validate the
    canonical set, not accept any string. An "Article" (PascalCase)
    instead of "article" must raise."""
    raw = _article_payload()
    raw["surface_type"] = "Article"

    with pytest.raises(ValueError, match="invalid surface_type"):
        _deserialize_reference(raw)


def test_deserialize_reference_rejects_missing_surface_id():
    """Defensive: surface_id is required."""
    raw = _article_payload()
    raw.pop("surface_id")

    with pytest.raises(ValueError, match="surface_id"):
        _deserialize_reference(raw)


def test_deserialize_video_caption_reference():
    """Video caption references carry caption_index +
    timestamp_start_seconds; paragraph_id is absent."""
    surface_id = uuid4()
    surface_entry_id = uuid4()
    raw = {
        "surface_type": "video_caption",
        "surface_id": str(surface_id),
        "surface_entry_id": str(surface_entry_id),
        "surface_title": "How to make karjalanpiirakka",
        "caption_index": 12,
        "timestamp_start_seconds": 34.5,
        "snippet_text": "Tervetuloa kahvilaan.",
        "original_token_phrase": "kahvilaan",
        "token_count": 1,
        "morphology": {"case": "illative", "number": "singular"},
        "inflected_form_details_raw": '{"case":"illative","number":"singular"}',
        "language_code": "fi",
        "published_at": "2026-05-12T10:43:00Z",
    }
    ref = _deserialize_reference(raw)
    assert ref.surface_type == SURFACE_VIDEO_CAPTION
    assert ref.surface_entry_id == surface_entry_id
    assert ref.surface_title == "How to make karjalanpiirakka"
    assert ref.caption_index == 12
    assert ref.timestamp_start_seconds == 34.5
    assert ref.paragraph_id is None
    assert ref.morphology.case == "illative"


def test_deserialize_scenario_reference_with_turn():
    """Scenario references carry turn_index when positive. No
    morphology in Arc 1 (Arc 3 producer wires it)."""
    surface_id = uuid4()
    raw = {
        "surface_type": "scenario",
        "surface_id": str(surface_id),
        "surface_entry_id": str(surface_id),  # scenario has no entry split
        "turn_index": 4,
        "snippet_text": "Mitä saisi olla?",
        "original_token_phrase": "saisi",
        "token_count": 1,
        "language_code": "fi",
        "published_at": "2026-05-12T10:43:00Z",
    }
    ref = _deserialize_reference(raw)
    assert ref.surface_type == SURFACE_SCENARIO
    assert ref.turn_index == 4
    assert ref.surface_id == ref.surface_entry_id, "scenario surface has no entry/version split"
    assert ref.morphology.is_empty(), "Arc 1 scenario surface has no morphology yet"


def test_deserialize_exercise_prompt_reference():
    """Exercise prompt references carry prompt_segment_index."""
    surface_id = uuid4()
    raw = {
        "surface_type": "exercise_prompt",
        "surface_id": str(surface_id),
        "surface_entry_id": str(surface_id),  # exercise has no entry split
        "prompt_segment_index": 0,
        "snippet_text": "Täydennä lause: Minulla on hyvä ___.",
        "original_token_phrase": "ystävä",
        "token_count": 1,
        "language_code": "fi",
        "published_at": "2026-05-12T10:43:00Z",
    }
    ref = _deserialize_reference(raw)
    assert ref.surface_type == SURFACE_EXERCISE_PROMPT
    assert ref.prompt_segment_index == 0
    assert ref.surface_id == ref.surface_entry_id


def test_deserialize_page_empty():
    """Empty page: no items, no cursor. Per D6 ratification this is
    the valid Arc-1 response for scenario + exercise_prompt surface
    queries."""
    page = _deserialize_page({"items": []})
    assert isinstance(page, SurfacesPage)
    assert page.items == []
    assert page.next_page_key is None


def test_deserialize_page_with_cursor():
    """Page with multiple items + next_page_key."""
    raw = {
        "items": [_article_payload(), _article_payload(snippet_text="Snippet 2")],
        "next_page_key": "abc123base64",
    }
    page = _deserialize_page(raw)
    assert len(page.items) == 2
    assert page.next_page_key == "abc123base64"
    assert page.items[0].surface_type == SURFACE_ARTICLE
    assert page.items[1].snippet_text == "Snippet 2"


def test_deserialize_page_missing_items_key():
    """Defensive: server payload with no items key yields empty
    page, not crash."""
    page = _deserialize_page({})
    assert page.items == []
    assert page.next_page_key is None


def test_deserialize_morphology_full_shape():
    """Morphology parses the canonical omorfi tagger shape."""
    raw = {
        "case": "partitive",
        "number": "plural",
        "tense": "past",
        "mood": "indicative",
        "person": "3rd",
        "voice": "active",
        "clitics": ["kAAn"],
    }
    morph = _deserialize_morphology(raw)
    assert isinstance(morph, Morphology)
    assert morph.case == "partitive"
    assert morph.number == "plural"
    assert morph.tense == "past"
    assert morph.mood == "indicative"
    assert morph.person == "3rd"
    assert morph.voice == "active"
    assert morph.clitics == ("kAAn",)


def test_deserialize_morphology_partial_shape():
    """Nominal: case + number only. tense/mood/person/voice nil."""
    raw = {"case": "genitive", "number": "singular"}
    morph = _deserialize_morphology(raw)
    assert morph.case == "genitive"
    assert morph.number == "singular"
    assert morph.tense is None
    assert morph.is_empty() is False


def test_deserialize_morphology_none_or_empty():
    """None or empty dict yields an empty Morphology."""
    assert _deserialize_morphology(None).is_empty()
    assert _deserialize_morphology({}).is_empty()


def test_deserialize_batch_lookup():
    """Batch lookup response: per-item map of surface references +
    per-item map of counts."""
    item_a = uuid4()
    item_b = uuid4()
    raw = {
        "language_code": "fi",
        "surfaces_by_item": {
            str(item_a): [_article_payload(), _article_payload()],
            str(item_b): [],  # empty list = checked, none found
        },
        "counts_by_item": {
            str(item_a): {
                "article": 2,
                "video_caption": 0,
                "scenario": 0,
                "exercise_prompt": 0,
            },
            str(item_b): {
                "article": 0,
                "video_caption": 0,
                "scenario": 0,
                "exercise_prompt": 0,
            },
        },
    }
    result = _deserialize_batch_lookup(raw)
    assert isinstance(result, BatchLookupResult)
    assert result.language_code == "fi"
    assert item_a in result.surfaces_by_item
    assert item_b in result.surfaces_by_item
    assert len(result.surfaces_by_item[item_a]) == 2
    assert len(result.surfaces_by_item[item_b]) == 0
    assert result.counts_by_item[item_a]["article"] == 2
    assert result.counts_by_item[item_b]["article"] == 0


def test_deserialize_batch_lookup_skips_invalid_item_keys():
    """Defensive: invalid UUID keys in the map are silently
    dropped + logged, not raised."""
    valid_id = uuid4()
    raw = {
        "language_code": "fi",
        "surfaces_by_item": {
            str(valid_id): [_article_payload()],
            "not-a-uuid": [_article_payload()],
        },
        "counts_by_item": {},
    }
    result = _deserialize_batch_lookup(raw)
    assert valid_id in result.surfaces_by_item
    assert len(result.surfaces_by_item) == 1


def test_counts_by_surface_helpers():
    """CountsBySurface convenience methods: total + has_grounding."""
    counts = CountsBySurface(
        item_id=uuid4(),
        language_code="fi",
        article=3,
        video_caption=1,
        scenario=0,
        exercise_prompt=0,
    )
    assert counts.total == 4
    assert counts.has_grounding() is True

    empty = CountsBySurface(item_id=uuid4(), language_code="fi")
    assert empty.total == 0
    assert empty.has_grounding() is False


def test_parse_iso8601_with_zulu():
    """Z suffix (Go default RFC3339) must parse to UTC datetime."""
    dt = _parse_iso8601("2026-05-12T10:43:00Z")
    assert dt == datetime(2026, 5, 12, 10, 43, 0, tzinfo=timezone.utc)


def test_parse_iso8601_with_offset():
    """Explicit +00:00 offset must also parse to UTC."""
    dt = _parse_iso8601("2026-05-12T10:43:00+00:00")
    assert dt == datetime(2026, 5, 12, 10, 43, 0, tzinfo=timezone.utc)


def test_parse_iso8601_with_nanoseconds():
    """RFC3339Nano (Go default for time.Time JSON) carries fractional
    seconds; Python's fromisoformat handles them natively in 3.11+."""
    dt = _parse_iso8601("2026-05-12T10:43:00.123456789Z")
    # Python's resolution is microseconds, not nanoseconds — the
    # last 3 digits get truncated. That's fine for our use case
    # (millisecond-level recency is enough).
    assert dt.year == 2026
    assert dt.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_client_requires_learning_language_code():
    """D4 contract: empty learning_language_code raises ValueError
    BEFORE making the HTTP call."""
    from kielo_shared.content_bridge import ContentBridgeClient

    client = ContentBridgeClient("http://localhost:8080", api_key="dev")
    try:
        with pytest.raises(ValueError, match="learning_language_code"):
            await client.list_surfaces_for_item(
                uuid4(),
                learning_language_code="",
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_client_validates_surface_types_before_dispatch():
    """surface_types entries are validated against
    ALL_CONTENT_BRIDGE_SURFACE_TYPES BEFORE the HTTP call. Unknown
    values raise ValueError."""
    from kielo_shared.content_bridge import ContentBridgeClient

    client = ContentBridgeClient("http://localhost:8080", api_key="dev")
    try:
        with pytest.raises(ValueError, match="unknown surface_type"):
            await client.list_surfaces_for_item(
                uuid4(),
                learning_language_code="fi",
                surface_types=["not-a-surface"],  # type: ignore[list-item]
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_batch_lookup_validates_inputs():
    """Empty item_ids list AND >200 items both raise ValueError
    BEFORE the HTTP call."""
    from kielo_shared.content_bridge import ContentBridgeClient

    client = ContentBridgeClient("http://localhost:8080", api_key="dev")
    try:
        with pytest.raises(ValueError, match="item_ids is required"):
            await client.batch_lookup_surfaces(
                [],
                learning_language_code="fi",
            )

        with pytest.raises(ValueError, match="exceeds maxBatchItems"):
            await client.batch_lookup_surfaces(
                [uuid4() for _ in range(201)],
                learning_language_code="fi",
            )

        with pytest.raises(ValueError, match="learning_language_code"):
            await client.batch_lookup_surfaces(
                [uuid4()],
                learning_language_code="",
            )
    finally:
        await client.close()


class _ResponseStub:
    """Minimal stand-in for httpx.Response — only the methods the
    client actually consumes (raise_for_status + json)."""

    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


class _CapturingHttpClient:
    """Captures the .get/.post call args so tests can assert on the
    wire shape WITHOUT a real HTTP layer. Pattern matches the
    canonical kielo-shared httpx-client-monkeypatch style."""

    def __init__(self, response_payload: dict):
        self.calls: list[dict] = []
        self._response = _ResponseStub(response_payload)

    async def get(self, url, params=None, **kwargs):
        self.calls.append({"method": "GET", "url": url, "params": params or {}})
        return self._response

    async def post(self, url, json=None, params=None, **kwargs):
        self.calls.append({
            "method": "POST",
            "url": url,
            "json": json or {},
            "params": params or {},
        })
        return self._response

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_list_surfaces_forwards_distinct_by_when_set():
    """Arc 1.2 — when distinct_by_surface_entry_id=True, the client
    must forward distinct_by=surface_entry_id query param to the
    server. When False (default), the param MUST be omitted.

    Captures the call params via a stub http client so this is a
    strict wire-shape contract test without a real HTTP layer.
    """
    from kielo_shared.content_bridge import ContentBridgeClient

    stub = _CapturingHttpClient({"items": [], "next_page_key": None})
    client = ContentBridgeClient("http://test.invalid", api_key="dev")
    # Swap the internal httpx client for the stub. This is the
    # canonical kielo-shared dependency-injection seam for unit
    # tests.
    client._client = stub  # type: ignore[attr-defined]
    try:
        # With distinct_by=True, the call should carry the query
        # param.
        await client.list_surfaces_for_item(
            uuid4(),
            learning_language_code="fi",
            distinct_by_surface_entry_id=True,
        )
        last_call = stub.calls[-1]
        assert last_call["method"] == "GET"
        assert last_call["params"].get("distinct_by") == "surface_entry_id"

        # With distinct_by=False (default), the param MUST be
        # omitted (server treats omitted as off).
        await client.list_surfaces_for_item(
            uuid4(),
            learning_language_code="fi",
        )
        last_call2 = stub.calls[-1]
        assert "distinct_by" not in last_call2["params"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_batch_lookup_forwards_distinct_by_in_body():
    """Arc 1.2 — when batch_lookup is called with
    distinct_by_surface_entry_id=True, the client must include the
    JSON body field. When False (default), the field MUST be
    omitted."""
    from kielo_shared.content_bridge import ContentBridgeClient

    stub = _CapturingHttpClient(
        {
            "language_code": "fi",
            "surfaces_by_item": {},
            "counts_by_item": {},
        }
    )
    client = ContentBridgeClient("http://test.invalid", api_key="dev")
    client._client = stub  # type: ignore[attr-defined]
    try:
        # distinct_by=True path.
        await client.batch_lookup_surfaces(
            [uuid4()],
            learning_language_code="fi",
            distinct_by_surface_entry_id=True,
        )
        last_call = stub.calls[-1]
        assert last_call["method"] == "POST"
        assert last_call["json"].get("distinct_by_surface_entry_id") is True

        # distinct_by=False (default) — field MUST be omitted.
        await client.batch_lookup_surfaces(
            [uuid4()],
            learning_language_code="fi",
        )
        last_call2 = stub.calls[-1]
        assert "distinct_by_surface_entry_id" not in last_call2["json"]
    finally:
        await client.close()
