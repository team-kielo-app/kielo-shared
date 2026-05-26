"""TTS seam type definitions — mirrors `kielo-shared/seam/tts/types.go`.

Pydantic-free dataclasses so the seam stays import-cheap and usable
from any caller (kielolearn-engine, ingest, kielo-convo python_agent).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator, Optional, Protocol


class ErrorClass(str, Enum):
    """Bounded categorization of provider failures. Matches the
    Go-side `tts.ErrorClass` so dashboards / alerts can pivot on a
    single label vocabulary across processes."""

    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    CLIENT_ERROR = "http_4xx"
    SERVER_ERROR = "http_5xx"
    READ_BODY = "read_body"
    MARSHAL = "marshal"
    EMPTY_RESPONSE = "empty_response"


@dataclass(frozen=True)
class Request:
    """Caller-supplied TTS input. Matches the Go-side `tts.Request`
    field set so call-sites can be ported between processes
    one-for-one.

    Required: ``text``, ``task``. Voice / speed / model / instructions
    are provider-specific and may be left unset.
    """

    text: str
    task: str
    voice_id: str = ""
    speed: float = 0.0
    model: str = ""
    instructions: str = ""


@dataclass(frozen=True)
class Result:
    audio: bytes
    provider: str
    latency_ms: int


class Error(Exception):
    """Standard provider error. Wraps the underlying exception with
    a bounded ``ErrorClass`` for metric labels and caller-side retry
    / breaker decisions."""

    def __init__(self, error_class: ErrorClass, cause: Optional[BaseException] = None):
        self.error_class = error_class
        self.cause = cause
        message = error_class.value
        if cause is not None:
            message = f"{error_class.value}: {cause}"
        super().__init__(message)


def class_of(err: Optional[BaseException]) -> str:
    """Extract an ErrorClass string from any exception. Non-seam
    exceptions collapse to `unknown` so the metric label set stays
    bounded.
    """
    if err is None:
        return ""
    if isinstance(err, Error):
        return err.error_class.value
    return ErrorClass.UNKNOWN.value


class Provider(Protocol):
    """Narrow seam interface. Implementations MUST be safe for
    concurrent use — engine-side TTS jobs run from per-paragraph
    asyncio tasks."""

    async def synthesize(self, request: Request) -> Result: ...


class StreamingProvider(Protocol):
    """Optional streaming companion to ``Provider``. Implementations
    yield raw audio bytes as the upstream provider produces them so
    callers can flush to clients incrementally (chunked transfer,
    Pub/Sub partial frames). The same metric labels apply — the
    decorator emits one ``kielo_tts_calls_total`` increment per
    stream when iteration completes (or raises).
    """

    def synthesize_stream(self, request: Request) -> AsyncIterator[bytes]: ...
