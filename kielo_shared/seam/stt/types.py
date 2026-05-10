"""STT seam type definitions — Phase STT-1.

Factory-shaped (no streaming transcript Protocol yet). The seam's
``create_realtime_stt`` returns whatever the underlying provider
expects to feed into ``livekit.agents.AgentSession(stt=...)``.
Type-checked as ``Any`` so callers don't pull in livekit type
imports here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol


class ErrorClass(str, Enum):
    """Bounded categorization of seam construction failures."""

    MISSING_KEY = "missing_key"
    INVALID_LANGUAGE = "invalid_language"
    INVALID_REQUEST = "invalid_request"
    PROVIDER_ERROR = "provider_error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RealtimeSTTRequest:
    """Caller-supplied STT factory inputs.

    Required: ``task``, ``model``, ``language``. Keyterms are tuple
    (immutable) so the dataclass stays frozen-hashable. Metadata is
    free-form and is NOT propagated to the metric label set —
    label cardinality is bounded to the explicit fields.
    """

    task: str
    model: str
    language: str
    keyterms: tuple[str, ...] = ()
    smart_format: bool = True
    punctuate: bool = True
    filler_words: bool = True
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RealtimeSTTResult:
    """Construction-time provenance. Returned alongside the STT
    object only on the metrics-decorator path (see metrics.py)."""

    provider: str
    task: str
    model: str
    language: str


class Error(Exception):
    """Standard seam error."""

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


class RealtimeSTTProvider(Protocol):
    """Narrow factory seam. ``provider_id`` is read-only and must
    be safe to call before / after ``create_realtime_stt``.
    """

    @property
    def provider_id(self) -> str: ...

    def create_realtime_stt(self, request: RealtimeSTTRequest) -> Any: ...
