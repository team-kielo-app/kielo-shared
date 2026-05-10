"""Python LLM seam type definitions."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Optional, Protocol


class ErrorClass(str, Enum):
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    CLIENT_ERROR = "http_4xx"
    SERVER_ERROR = "http_5xx"
    DECODE = "decode"
    EMPTY_RESPONSE = "empty_response"
    MISSING_PAYLOAD = "missing_payload"
    INVALID_REQUEST = "invalid_request"
    PROVIDER_ERROR = "provider_error"


@dataclass(frozen=True)
class Request:
    prompt: str
    task: str
    model: str = ""
    system_prompt: str = ""
    response_mime_type: str = ""
    response_schema: Optional[dict] = None
    temperature: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Result:
    raw_text: str
    provider: str
    latency_ms: int


class Error(Exception):
    def __init__(self, error_class: ErrorClass, cause: Optional[BaseException] = None):
        self.error_class = error_class
        self.cause = cause
        message = error_class.value
        if cause is not None:
            message = f"{error_class.value}: {cause}"
        super().__init__(message)


def class_of(err: Optional[BaseException]) -> str:
    if err is None:
        return ""
    if isinstance(err, Error):
        return err.error_class.value
    return ErrorClass.UNKNOWN.value


class Provider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def generate(self, request: Request) -> Result: ...


class StreamingProvider(Protocol):
    """Optional streaming companion. Implementations yield text
    tokens as the upstream produces them; metrics decorator emits
    one record per stream when iteration completes.
    """

    def generate_stream(self, request: Request) -> AsyncIterator[str]: ...
