"""kielo_shared.content_bridge.client — HTTP client for the Content
Bridge Arc 1 reader endpoints owned by kielo-content-service.

Endpoints (verified live 2026-06-07):

    GET  <content-service>/internal/content-bridge/items/{item_id}/surfaces
    GET  <content-service>/internal/content-bridge/items/{item_id}/surfaces/count
    POST <content-service>/internal/content-bridge/items/lookup

The paths are /internal/content-bridge/* NOT /internal/api/v3/content-bridge/*.
content-service's openapi.NewWrapper roots /internal/* routes at
/internal/<path> (the /api/v3 prefix only appears in the OAS spec
metadata for cross-service discovery purposes — the actual Echo route
is shorter). Sibling routes follow the same pattern:
/internal/klearn/..., /internal/dictionary/..., etc.

The client uses the canonical kielo_shared.http.internal_client_async
hook chain (trace context propagation + active-language header
forwarding + X-Internal-API-Key default) so behavior is consistent
with the rest of the engine's HTTP surface.

Active-language requirement: every Bridge endpoint REQUIRES the
learning_language_code parameter per D4 pure per-language. Callers
MUST pass `learning_language_code` to every method. The server
validates against the supported set (fi, sv today) and 400s on
unsupported codes; the client raises ValueError for empty input
before hitting the wire.

Wire-shape parity (Arc 1 audit hardening, 2026-06-07):

- surface_entry_id is REQUIRED in the response per Arc 1 wire shape.
  The client does NOT fall back to surface_id if absent — that
  silent fallback would route notification deep links to the wrong
  URL the moment a future server forgot to emit the field. Missing
  surface_entry_id raises ValueError so producer-side regressions
  surface immediately rather than silently corrupting routing.

- surface_type values are validated against the canonical set.
  Unknown strings raise ValueError (Sweep D casing-drift class).

- inflected_form_details is now structured (`morphology` dict +
  `inflected_form_details_raw` for forensic forward-compat).
  Pre-audit the field was a plain string label like "nom sg";
  the actual server emits {"case": "partitive", ...}. The
  string-typed dataclass field was a wire-shape lie.

- position dropped (Sweep KK class — meant "paragraph position"
  in the ADR but populated from `start_word_index`). Consumers
  that want word position read `start_word_index` directly.

- token_count surfaced so consumers can gate notification
  rendering on multi-word phrases (7.5% of production rows in
  cms_fi are multi-token, e.g. "Kaikkia kiekko ei kuitenkaan
  voisi vähempää kiinnostaa").

- surface_title surfaced. Empty for scenario + exercise_prompt
  until Arcs 3+2 wire producers; populated for article +
  video_caption.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional
from uuid import UUID

from kielo_shared.envelope import unwrap_envelope
from kielo_shared.http import internal_client_async

from kielo_shared.vocab.content_bridge_surface_type import (
    ALL_CONTENT_BRIDGE_SURFACE_TYPES,
    ContentBridgeSurfaceType,
    is_valid_content_bridge_surface_type,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Morphology:
    """Parsed morphology from cms_<lang>.occurrences.inflected_form_details.

    omorfi tagger produces the shape:

        {"case": "partitive", "number": "singular",
         "tense": null, "mood": null, "person": null,
         "voice": null, "clitics": []}

    Fields are None when the tagger did not produce that aspect
    (nominals carry case/number; verbs carry tense/mood/person/voice;
    pronouns carry the union).
    """

    case: Optional[str] = None
    number: Optional[str] = None
    tense: Optional[str] = None
    mood: Optional[str] = None
    person: Optional[str] = None
    voice: Optional[str] = None
    clitics: tuple[str, ...] = field(default_factory=tuple)

    def is_empty(self) -> bool:
        return (
            self.case is None
            and self.number is None
            and self.tense is None
            and self.mood is None
            and self.person is None
            and self.voice is None
            and not self.clitics
        )


@dataclass(frozen=True)
class SurfaceReference:
    """One row of the Bridge response. Mirrors the Go-side
    content_bridge.SurfaceReference struct field-for-field.

    Pointer-typed fields on the Go side become Optional here.
    """

    surface_type: ContentBridgeSurfaceType
    surface_id: UUID
    # surface_entry_id is the routing/deep-link identifier (distinct
    # from surface_id for article + video_caption where content-service
    # uses an entry/version split). Mobile deep links use this value:
    #   kielo://content/article/{surface_entry_id}
    #   kielo://content/video/{surface_entry_id}
    surface_entry_id: UUID
    language_code: str
    published_at: datetime

    # Always-non-empty for article + video_caption; empty for
    # scenario + exercise_prompt in Arc 1 (producer wires in
    # Arcs 3+2).
    surface_title: str = ""

    # Snippet sourcing depends on surface_type. For article, the
    # cms_<lang>.paragraphs.text JOIN populates it. For video,
    # scenario, and exercise_prompt the producer wires it
    # (currently empty).
    snippet_text: str = ""

    # The surface form at this occurrence ("ystäväksi"). May be
    # multi-token. Consumers wanting to render "you met X"
    # notifications must check token_count <= 2.
    original_token_phrase: str = ""
    token_count: int = 0

    # Parsed morphology. is_empty() when the producer did not
    # capture morphology OR when JSON parsing failed (server-side
    # logs the parse error; client sees an empty Morphology).
    morphology: Morphology = field(default_factory=Morphology)

    # Raw morphology JSON for forensic forward-compat (new omorfi
    # tags land here even when not yet modeled in Morphology).
    inflected_form_details_raw: str = ""

    # Per-surface position fields. Only the relevant one is
    # populated for each surface_type.
    paragraph_id: Optional[UUID] = None
    caption_index: Optional[int] = None
    timestamp_start_seconds: Optional[float] = None
    turn_index: Optional[int] = None
    prompt_segment_index: Optional[int] = None

    # The word offset within the paragraph for article. None when
    # not captured. Schema-nullable.
    start_word_index: Optional[int] = None


@dataclass(frozen=True)
class SurfacesPage:
    """Wire response of the Bridge reader. Matches the Go-side
    content_bridge.SurfacesResponse: items + optional next_page_key."""

    items: list[SurfaceReference] = field(default_factory=list)
    next_page_key: Optional[str] = None


@dataclass(frozen=True)
class CountsBySurface:
    """Per-surface counts from
    GET /internal/content-bridge/items/{id}/surfaces/count.

    Always includes ALL 4 surface types so consumers can directly
    compare across surfaces (no need to handle missing keys).
    """

    item_id: UUID
    language_code: str
    article: int = 0
    video_caption: int = 0
    scenario: int = 0
    exercise_prompt: int = 0

    @property
    def total(self) -> int:
        return self.article + self.video_caption + self.scenario + self.exercise_prompt

    def has_grounding(self) -> bool:
        return self.total > 0


@dataclass(frozen=True)
class BatchLookupResult:
    """Wire response of POST /internal/content-bridge/items/lookup.

    Each requested item_id appears in surfaces_by_item with either
    its surface list OR an empty list (so consumers can distinguish
    "checked, none found" from "not requested").
    """

    language_code: str
    surfaces_by_item: Mapping[UUID, list[SurfaceReference]]
    counts_by_item: Mapping[UUID, Mapping[str, int]]


class ContentBridgeClient:
    """HTTP client for the kielo-content-service Content Bridge
    reader endpoints.

    Three methods cover the canonical consumer paths:

    - `list_surfaces_for_item` — Author B, popover, recommender
      single-item lookup.
    - `count_surfaces_for_item` — Author D, admin coverage.
    - `batch_lookup_surfaces` — recommendation engine cold-start,
      bulk audits.

    Empty-surface semantics: when the caller asks for
    surface_types=[SURFACE_SCENARIO] or SURFACE_EXERCISE_PROMPT in
    Arc 1, the response includes the requested surface with an
    empty list — NOT an error. Producers wire in Arcs 2+3.
    Operator-ratified D6 contract; don't silently filter to
    populated surfaces only (that would mask the empty contract
    from consumers).
    """

    def __init__(
        self,
        content_service_url: str,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        caller: str = "unknown",
    ):
        # Normalize: callers may pass either the bare service URL
        # (http://localhost:8086) or the public-API-prefixed URL
        # (http://localhost:8086/api/v3). The Bridge reader is at
        # /internal/..., so strip the public /api/v3 suffix if
        # present. Mirrors achievement_client._normalize_base_url.
        trimmed = content_service_url.rstrip("/")
        for suffix in ("/api/v3", "/api"):
            if trimmed.endswith(suffix):
                trimmed = trimmed[: -len(suffix)]
                break
        self.content_service_url = trimmed
        self.api_key = api_key
        self._timeout = timeout
        # caller identifies the consumer for metric attribution.
        # Server coerces unknown values to "unknown" via the bounded
        # AllowedContentBridgeCallers set; passing it directly here
        # means we don't have to re-set it per call.
        self._caller = caller
        self._client = internal_client_async(
            api_key=api_key,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def list_surfaces_for_item(
        self,
        item_id: UUID,
        *,
        learning_language_code: str,
        surface_types: Optional[list[ContentBridgeSurfaceType]] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        exclude_surface_entry_ids: Optional[list[UUID]] = None,
        distinct_by_surface_entry_id: bool = False,
    ) -> SurfacesPage:
        """GET /internal/content-bridge/items/{item_id}/surfaces.

        Args:
            item_id: UUID of the base_word or grammar_concept to look up.
            learning_language_code: REQUIRED per D4. Must be a
                supported learning language (fi, sv today).
            surface_types: Optional subset of the 4 canonical
                surface types. Empty/None means "all surfaces".
            limit: Page size; default 50, server caps at 200.
            cursor: Opaque next_page_key from a previous response.
            exclude_surface_entry_ids: UUIDs to drop from results.
                Per-request only; the client does NOT track shown
                IDs across calls.
            distinct_by_surface_entry_id: Arc 1.2 — when True, the
                server collapses row-per-occurrence into row-per-
                surface (latest occurrence wins per
                (surface_type, surface_entry_id) tuple). Saves 17-
                25% bandwidth on popular items. Use this when you
                want "places where the word appears" rather than
                "every occurrence of the word".

        Returns:
            SurfacesPage with items list + optional next_page_key.

        Raises:
            ValueError if learning_language_code is empty OR if a
            surface_types entry is not in
            ALL_CONTENT_BRIDGE_SURFACE_TYPES.
            httpx.HTTPStatusError on 4xx/5xx responses (the caller
            decides whether to retry / fall back / surface the error).
        """
        if not learning_language_code:
            raise ValueError("learning_language_code is required (D4)")
        if surface_types:
            for s in surface_types:
                if not is_valid_content_bridge_surface_type(s):
                    raise ValueError(
                        f"unknown surface_type: {s!r} "
                        f"(expected one of {sorted(ALL_CONTENT_BRIDGE_SURFACE_TYPES)})"
                    )

        # URL kept on a single line so the Sweep ZL cross-service
        # proxy contract gate's line-scoped regex resolver can
        # resolve the literal path. Multi-line concatenated paths
        # defeat the resolver.
        path = f"{self.content_service_url}/internal/content-bridge/items/{item_id}/surfaces"

        params: dict[str, Any] = {
            "learning_language_code": learning_language_code,
            "limit": limit,
            "caller": self._caller,
        }
        if surface_types:
            params["surface_type"] = ",".join(str(s) for s in surface_types)
        if cursor:
            params["next_page_key"] = cursor
        if exclude_surface_entry_ids:
            params["exclude_surface_entry_ids"] = ",".join(
                str(eid) for eid in exclude_surface_entry_ids
            )
        if distinct_by_surface_entry_id:
            params["distinct_by"] = "surface_entry_id"

        response = await self._client.get(path, params=params)
        response.raise_for_status()
        payload = unwrap_envelope(response.json())

        return _deserialize_page(payload)

    async def count_surfaces_for_item(
        self,
        item_id: UUID,
        *,
        learning_language_code: str,
    ) -> CountsBySurface:
        """GET /internal/content-bridge/items/{item_id}/surfaces/count.

        Returns per-surface counts without fetching rows. Use when
        you only need to answer "does this item have any grounding?"
        or "how many references per surface?" without paying for
        the row data.

        Args:
            item_id: UUID of the base_word or grammar_concept.
            learning_language_code: REQUIRED per D4.

        Returns:
            CountsBySurface dataclass with per-surface counts +
            total + has_grounding() convenience method.

        Raises:
            ValueError on empty learning_language_code.
            httpx.HTTPStatusError on 4xx/5xx.
        """
        if not learning_language_code:
            raise ValueError("learning_language_code is required (D4)")

        path = f"{self.content_service_url}/internal/content-bridge/items/{item_id}/surfaces/count"
        params = {
            "learning_language_code": learning_language_code,
            "caller": self._caller,
        }
        response = await self._client.get(path, params=params)
        response.raise_for_status()
        payload = unwrap_envelope(response.json())

        counts = payload.get("counts_by_surface") or {}
        return CountsBySurface(
            item_id=UUID(payload["item_id"]),
            language_code=payload.get("language_code", ""),
            article=int(counts.get("article", 0)),
            video_caption=int(counts.get("video_caption", 0)),
            scenario=int(counts.get("scenario", 0)),
            exercise_prompt=int(counts.get("exercise_prompt", 0)),
        )

    async def batch_lookup_surfaces(
        self,
        item_ids: list[UUID],
        *,
        learning_language_code: str,
        surface_types: Optional[list[ContentBridgeSurfaceType]] = None,
        per_item_limit: int = 5,
        exclude_surface_entry_ids: Optional[list[UUID]] = None,
        distinct_by_surface_entry_id: bool = False,
    ) -> BatchLookupResult:
        """POST /internal/content-bridge/items/lookup.

        Bulk variant of list_surfaces_for_item — returns surfaces
        for up to 200 item_ids in one round-trip. Designed for the
        recommendation engine cold-start path and Author D's bulk
        coverage audits.

        Each requested item_id appears in the response's
        surfaces_by_item map with either its surface list OR an
        empty list (so consumers can distinguish "checked, none
        found" from "not requested").

        Args:
            item_ids: List of base_word/grammar_concept UUIDs.
                Empty list raises ValueError; over 200 raises
                ValueError too (server rejects with 400; client
                fails fast).
            learning_language_code: REQUIRED per D4.
            surface_types: Optional subset of canonical surfaces.
            per_item_limit: Per-item cap on returned surfaces.
                Default 5, max 50.
            exclude_surface_entry_ids: UUIDs to drop from results
                across all items.
            distinct_by_surface_entry_id: Arc 1.2 — when True,
                applies row-per-surface dedupe to each item's
                results (latest occurrence wins per
                (surface_type, surface_entry_id) tuple). Same
                semantics as the GET endpoint's distinct_by flag.

        Returns:
            BatchLookupResult with surfaces_by_item +
            counts_by_item maps keyed by UUID.

        Raises:
            ValueError on invalid inputs.
            httpx.HTTPStatusError on 4xx/5xx.
        """
        if not learning_language_code:
            raise ValueError("learning_language_code is required (D4)")
        if not item_ids:
            raise ValueError("item_ids is required and must not be empty")
        if len(item_ids) > 200:
            raise ValueError(
                f"item_ids exceeds maxBatchItems=200 (got {len(item_ids)})"
            )
        if surface_types:
            for s in surface_types:
                if not is_valid_content_bridge_surface_type(s):
                    raise ValueError(
                        f"unknown surface_type: {s!r} "
                        f"(expected one of {sorted(ALL_CONTENT_BRIDGE_SURFACE_TYPES)})"
                    )

        path = f"{self.content_service_url}/internal/content-bridge/items/lookup"
        body: dict[str, Any] = {
            "item_ids": [str(i) for i in item_ids],
            "learning_language_code": learning_language_code,
            "per_item_limit": per_item_limit,
        }
        if surface_types:
            body["surface_types"] = [str(s) for s in surface_types]
        if exclude_surface_entry_ids:
            body["exclude_surface_entry_ids"] = [
                str(eid) for eid in exclude_surface_entry_ids
            ]
        if distinct_by_surface_entry_id:
            body["distinct_by_surface_entry_id"] = True

        params = {"caller": self._caller}
        response = await self._client.post(path, json=body, params=params)
        response.raise_for_status()
        payload = unwrap_envelope(response.json())

        return _deserialize_batch_lookup(payload)


def _deserialize_page(payload: dict[str, Any]) -> SurfacesPage:
    """Wire → typed conversion for the list endpoint."""
    raw_items = payload.get("items") or []
    items: list[SurfaceReference] = []
    for raw in raw_items:
        items.append(_deserialize_reference(raw))
    return SurfacesPage(
        items=items,
        next_page_key=payload.get("next_page_key"),
    )


def _deserialize_batch_lookup(payload: dict[str, Any]) -> BatchLookupResult:
    """Wire → typed conversion for the batch lookup endpoint."""
    raw_by_item = payload.get("surfaces_by_item") or {}
    surfaces_by_item: dict[UUID, list[SurfaceReference]] = {}
    for item_str, raw_items in raw_by_item.items():
        try:
            item_uuid = UUID(item_str)
        except (ValueError, TypeError):
            logger.warning(
                "content_bridge.batch_lookup: skipping invalid item key %r", item_str
            )
            continue
        surfaces_by_item[item_uuid] = [_deserialize_reference(r) for r in raw_items]

    raw_counts_by_item = payload.get("counts_by_item") or {}
    counts_by_item: dict[UUID, Mapping[str, int]] = {}
    for item_str, counts in raw_counts_by_item.items():
        try:
            item_uuid = UUID(item_str)
        except (ValueError, TypeError):
            continue
        counts_by_item[item_uuid] = {k: int(v) for k, v in counts.items()}

    return BatchLookupResult(
        language_code=payload.get("language_code", ""),
        surfaces_by_item=surfaces_by_item,
        counts_by_item=counts_by_item,
    )


def _deserialize_reference(raw: dict[str, Any]) -> SurfaceReference:
    """Wire → SurfaceReference.

    Strict on surface_type (Sweep D casing-drift class) and
    surface_entry_id (Arc 1 wire shape contract — no silent fallback
    to surface_id).
    """
    # Validate surface_type before constructing the typed enum.
    # Sweep D taught us that wire→typed casts must validate the
    # canonical set, not accept any string.
    raw_surface_type_any = raw.get("surface_type")
    raw_surface_type = (
        raw_surface_type_any if isinstance(raw_surface_type_any, str) else ""
    )
    if not is_valid_content_bridge_surface_type(raw_surface_type):
        raise ValueError(
            f"invalid surface_type: {raw_surface_type_any!r} "
            f"(expected one of {sorted(ALL_CONTENT_BRIDGE_SURFACE_TYPES)})"
        )

    surface_id_raw = raw.get("surface_id")
    if not surface_id_raw:
        raise ValueError("response missing surface_id")
    surface_id = UUID(surface_id_raw)

    # surface_entry_id is REQUIRED in Arc 1 wire shape. The pre-audit
    # client fell back to surface_id when absent — that silent fallback
    # would route notification deep links to the wrong URL the moment
    # a future server forgot to emit the field. Fail loudly instead.
    surface_entry_id_raw = raw.get("surface_entry_id")
    if not surface_entry_id_raw:
        raise ValueError(
            "response missing surface_entry_id (Arc 1 wire shape requires it; "
            "consumer deep links route through this field)"
        )
    surface_entry_id = UUID(surface_entry_id_raw)

    # Morphology is a nested object; absent or null → empty
    # Morphology dataclass.
    morph = _deserialize_morphology(raw.get("morphology"))

    return SurfaceReference(
        surface_type=ContentBridgeSurfaceType(raw_surface_type),
        surface_id=surface_id,
        surface_entry_id=surface_entry_id,
        surface_title=raw.get("surface_title", ""),
        snippet_text=raw.get("snippet_text", ""),
        original_token_phrase=raw.get("original_token_phrase", ""),
        token_count=int(raw.get("token_count", 0)),
        morphology=morph,
        inflected_form_details_raw=raw.get("inflected_form_details_raw", ""),
        language_code=raw.get("language_code", ""),
        published_at=_parse_iso8601(raw["published_at"]),
        paragraph_id=UUID(raw["paragraph_id"]) if raw.get("paragraph_id") else None,
        caption_index=raw.get("caption_index"),
        timestamp_start_seconds=raw.get("timestamp_start_seconds"),
        turn_index=raw.get("turn_index"),
        prompt_segment_index=raw.get("prompt_segment_index"),
        start_word_index=raw.get("start_word_index"),
    )


def _deserialize_morphology(raw: Optional[dict[str, Any]]) -> Morphology:
    """Wire → Morphology. Missing or None → empty Morphology."""
    if not raw:
        return Morphology()
    clitics_raw = raw.get("clitics") or ()
    return Morphology(
        case=raw.get("case"),
        number=raw.get("number"),
        tense=raw.get("tense"),
        mood=raw.get("mood"),
        person=raw.get("person"),
        voice=raw.get("voice"),
        clitics=tuple(clitics_raw),
    )


def _parse_iso8601(value: str) -> datetime:
    """RFC3339 → datetime. The Go server emits time.Time as RFC3339Nano
    which Python's fromisoformat handles natively for 3.11+. The
    engine runs on 3.13 so this is safe."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
