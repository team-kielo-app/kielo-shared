"""kielo_shared.localization.dynclient — Python HTTP client for
kielo-localization's dynamic_translations surface (ADR-012 §D2.6
Phase 2). Mirror of the Go client in
kielo-shared/localization/dynclient/client.go; both share the
wire JSON shape so cross-language callers see identical
semantics.

Usage:

    from kielo_shared.localization.dynclient import (
        DynClient,
        UpsertRequest,
        FetchRequest,
    )

    client = DynClient(
        base_url="http://kielo-localization:8080",
        api_key=settings.KIELO_INTERNAL_API_KEY,
    )
    try:
        await client.upsert(
            UpsertRequest(
                resource_type="article.paragraph",
                resource_id=str(paragraph_id),
                source_version=source_version_from_text(english),
                language_code="vi",
                translated_text=translated,
                source_locale="en",
                translator_source="lazy_translation",
            )
        )
    finally:
        await client.aclose()

The client is async-only (matches the kielolearn-engine + content-
service callers that own the writers). All requests gate on the
internal API key header (X-Internal-API-Key); the underlying
``kielo_shared.http.internal_client_async`` adds it as a default
header along with the canonical trace + locale hooks.

Errors raise ``DynClientError`` with the upstream status + body
included so logs are debuggable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from kielo_shared.http import internal_client_async

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30.0


class DynClientError(RuntimeError):
    """Raised when kielo-localization returns a non-2xx response.

    Includes the upstream status + a (capped) prefix of the body
    so the caller can surface a meaningful error log without
    blowing up on accidental HTML error pages.
    """

    def __init__(self, op: str, status: int, body: str) -> None:
        capped = body[:512] if body else ""
        super().__init__(f"dynclient: {op} returned {status}: {capped}")
        self.op = op
        self.status = status
        self.body = body


@dataclass(slots=True)
class UpsertRequest:
    """Mirrors kielo-localization's UpsertDynamicTranslationRequest.

    SourceVersion is caller-supplied (typically
    ``source_version_from_text(english)``); status and
    translator_source default to ``"machine"`` /
    ``"lazy_translation"`` at the service when blank.
    """

    resource_type: str
    resource_id: str
    source_version: str
    language_code: str
    translated_text: str
    status: str = ""
    source_locale: str = ""
    translator_source: str = ""
    reviewer_id: str = ""  # uuid; empty = uuid.Nil = NULL on column

    def to_payload(self) -> dict:
        payload = {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "source_version": self.source_version,
            "language_code": self.language_code,
            "translated_text": self.translated_text,
        }
        # Optional fields are omitted when blank so the wire JSON
        # stays minimal and the service-side defaults kick in.
        if self.status:
            payload["status"] = self.status
        if self.source_locale:
            payload["source_locale"] = self.source_locale
        if self.translator_source:
            payload["translator_source"] = self.translator_source
        if self.reviewer_id:
            payload["reviewer_id"] = self.reviewer_id
        return payload


@dataclass(slots=True)
class DynamicTranslation:
    """Mirrors kielo-localization models.DynamicTranslation. Only
    the fields the Python callers consume are typed; extras would
    round-trip through ``extra`` (not used today).
    """

    id: str
    resource_type: str
    resource_id: str
    source_version: str
    language_code: str
    translated_text: str
    status: str = ""
    source_locale: Optional[str] = None
    translator_source: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: dict) -> "DynamicTranslation":
        return cls(
            id=payload.get("id", ""),
            resource_type=payload.get("resource_type", ""),
            resource_id=payload.get("resource_id", ""),
            source_version=payload.get("source_version", ""),
            language_code=payload.get("language_code", ""),
            translated_text=payload.get("translated_text", ""),
            status=payload.get("status", ""),
            source_locale=payload.get("source_locale"),
            translator_source=payload.get("translator_source"),
            reviewed_by=payload.get("reviewed_by"),
            reviewed_at=payload.get("reviewed_at"),
            created_at=payload.get("created_at"),
            updated_at=payload.get("updated_at"),
        )


@dataclass(slots=True)
class UpsertResponse:
    """Returned from POST /dynamic. ``inserted`` distinguishes a
    fresh insert from an update on an existing row (xmax = 0
    idiom on the service side).
    """

    row: Optional[DynamicTranslation]
    inserted: bool

    @classmethod
    def from_payload(cls, payload: dict) -> "UpsertResponse":
        row_payload = payload.get("row")
        row = DynamicTranslation.from_payload(row_payload) if row_payload else None
        return cls(row=row, inserted=bool(payload.get("inserted")))


@dataclass(slots=True)
class FetchRequest:
    """Mirrors kielo-localization's
    FetchDynamicTranslationsRequest.

    At least one of ``resource_ids`` / ``resource_id_prefix`` MUST
    be set — the service rejects with 400 otherwise to prevent
    accidental full-table scans.
    """

    resource_types: List[str]
    resource_ids: List[str] = field(default_factory=list)
    resource_id_prefix: str = ""
    language_code: str = ""

    def to_payload(self) -> dict:
        payload: dict = {"resource_types": self.resource_types}
        if self.resource_ids:
            payload["resource_ids"] = self.resource_ids
        if self.resource_id_prefix:
            payload["resource_id_prefix"] = self.resource_id_prefix
        if self.language_code:
            payload["language_code"] = self.language_code
        return payload


@dataclass(slots=True)
class FetchResponse:
    items: List[DynamicTranslation]

    @classmethod
    def from_payload(cls, payload: dict) -> "FetchResponse":
        items_raw = payload.get("items") or []
        return cls(items=[DynamicTranslation.from_payload(item) for item in items_raw])


class DynClient:
    """Async HTTP client for kielo-localization's
    dynamic_translations surface.

    Thread-safe in the asyncio sense (an httpx.AsyncClient is OK
    to share across tasks). One instance per process is fine.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._owned_client = client is None
        self._client: Optional[httpx.AsyncClient] = client
        self._timeout = timeout

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = internal_client_async(
                base_url=self._base_url,
                api_key=self._api_key,
                timeout=self._timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owned_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def upsert(self, request: UpsertRequest) -> UpsertResponse:
        """POST /internal/api/v3/localization/dynamic.

        Returns the persisted row + a bool that distinguishes a
        fresh insert (HTTP 201) from an in-place update (HTTP 200).
        Callers that don't care which path it took can ignore the
        flag.
        """
        client = await self._ensure_client()
        resp = await client.post(
            "/internal/api/v3/localization/dynamic",
            json=request.to_payload(),
        )
        if resp.status_code not in (200, 201):
            raise DynClientError("upsert", resp.status_code, resp.text)
        return UpsertResponse.from_payload(resp.json())

    async def fetch_by_resources(self, request: FetchRequest) -> FetchResponse:
        """POST /internal/api/v3/localization/dynamic/fetch.

        Returns up to one row per (resource_type, resource_id,
        language_code) tuple — the freshest visible row (status
        in machine / pending_review / approved / override).
        """
        client = await self._ensure_client()
        resp = await client.post(
            "/internal/api/v3/localization/dynamic/fetch",
            json=request.to_payload(),
        )
        if resp.status_code != 200:
            raise DynClientError("fetch", resp.status_code, resp.text)
        return FetchResponse.from_payload(resp.json())


__all__ = [
    "DynClient",
    "DynClientError",
    "DynamicTranslation",
    "FetchRequest",
    "FetchResponse",
    "UpsertRequest",
    "UpsertResponse",
    "DEFAULT_TIMEOUT",
]
