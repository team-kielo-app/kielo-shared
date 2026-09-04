"""One signal for "an external API we pay for failed".

Every third-party dependency (LLM, TTS, STT, RevenueCat, push, email,
translation) already has its own metric family, but the Prometheus sidecars
that read those families were retired in 2026-08, so none of them reaches an
alert today. This module emits ONE canonical WARNING log line per failure,
with a bounded ``kind`` vocabulary, so a single Cloud Logging log-based
metric (``terraform/external-api-monitoring.tf``) can page on it. The
``kind`` matters most: ``quota`` and ``auth`` mean "we ran out of credits or
the key died" and page on the first occurrence; everything else pages on a
sustained rate.

Log line shape (keep stable; the terraform filter matches these tokens)::

    external_api_failure provider=deepgram operation=speech_eval kind=quota status=402 service=kielolearn-engine detail=...

The Go twin is ``kielo-shared/observe/metrics/external_api.go``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from kielo_shared.observability.metrics import PROMETHEUS_AVAILABLE

logger = logging.getLogger("kielo_shared.observability.external_api")

LOG_TOKEN = "external_api_failure"

KIND_QUOTA = "quota"
KIND_AUTH = "auth"
KIND_RATE_LIMIT = "rate_limit"
KIND_TIMEOUT = "timeout"
KIND_CONNECTION = "connection"
KIND_SERVER = "server"
KIND_CLIENT = "client"
KIND_UNKNOWN = "unknown"

# Kinds that mean "money or credentials", not "the provider hiccupped".
CREDIT_KINDS = frozenset({KIND_QUOTA, KIND_AUTH})

_QUOTA_MARKERS = (
    "quota",
    "billing",
    "insufficient",
    "credit",
    "balance",
    "payment",
    "exceeded your current",
    "resource_exhausted",
    "resourceexhausted",
    "resource has been exhausted",
    "plan limit",
    "out of funds",
)
_AUTH_MARKERS = (
    "unauthorized",
    "invalid api key",
    "invalid_api_key",
    "api key not valid",
    "authentication",
    "permission denied",
    "forbidden",
    "invalid credentials",
    "token expired",
)
_TIMEOUT_MARKERS = ("timeout", "timed out", "deadline")
_CONNECTION_MARKERS = ("connect", "dns", "resolve", "reset by peer", "unreachable")

_EXTERNAL_API_FAILURE_TOTAL: Any = None
if PROMETHEUS_AVAILABLE:
    try:
        from prometheus_client import Counter

        _EXTERNAL_API_FAILURE_TOTAL = Counter(
            "kielo_external_api_failure_total",
            "External (paid) API failures by provider and bounded kind. "
            "kind=quota|auth means credits or credentials, not a transient error.",
            ["service", "provider", "kind"],
        )
    except Exception:  # duplicate registration in odd import orders
        _EXTERNAL_API_FAILURE_TOTAL = None


def service_name() -> str:
    """Cloud Run sets K_SERVICE; local compose sets SERVICE_NAME on most
    services. Never raises."""
    return (
        os.environ.get("K_SERVICE")
        or os.environ.get("SERVICE_NAME")
        or os.environ.get("OTEL_SERVICE_NAME")
        or "unknown"
    )


def classify_external_api_failure(
    status: int | None = None,
    message: str = "",
    error_class: str = "",
) -> str:
    """Map an HTTP status and/or error text to the bounded ``kind`` vocabulary.

    Order matters: a 429 whose body talks about quota or billing is ``quota``
    (Gemini and OpenAI both return 429 for "you are out of credits" and for
    plain rate limiting); a bare 429 is ``rate_limit``. 402 is always
    ``quota``. 401/403 are ``auth``. ``error_class`` is the seam's own label
    (``timeout`` / ``connection`` / ``http_5xx`` / ...) and is used when no
    status is known.
    """
    msg = (message or "").lower()
    cls = (error_class or "").lower()
    if status == 402 or any(marker in msg for marker in _QUOTA_MARKERS):
        return KIND_QUOTA
    if status in (401, 403) or any(marker in msg for marker in _AUTH_MARKERS):
        return KIND_AUTH
    if (
        status == 429
        or "rate limit" in msg
        or "ratelimit" in msg
        or "too many requests" in msg
    ):
        return KIND_RATE_LIMIT
    if cls == "timeout" or any(marker in msg for marker in _TIMEOUT_MARKERS):
        return KIND_TIMEOUT
    if cls == "connection" or any(marker in msg for marker in _CONNECTION_MARKERS):
        return KIND_CONNECTION
    if (status is not None and status >= 500) or cls == "http_5xx":
        return KIND_SERVER
    if (status is not None and 400 <= status < 500) or cls == "http_4xx":
        return KIND_CLIENT
    if cls in ("server_error", "provider_error"):
        return KIND_SERVER
    return KIND_UNKNOWN


def status_of(exc: BaseException | None) -> int | None:
    """Best-effort HTTP status from httpx/openai/google SDK exceptions."""
    if exc is None:
        return None
    for attr in ("status_code", "code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value <= 599:
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int) and 100 <= value <= 599:
        return value
    cause = getattr(exc, "cause", None) or getattr(exc, "__cause__", None)
    if isinstance(cause, BaseException) and cause is not exc:
        return status_of(cause)
    return None


def external_api_failure_emit(
    *,
    provider: str,
    operation: str,
    kind: str | None = None,
    status: int | None = None,
    exc: BaseException | None = None,
    error_class: str = "",
    detail: str = "",
    service: str | None = None,
) -> None:
    """Record one external API failure: WARNING log line (the alert signal)
    plus a Prometheus counter when available. Never raises.

    Pass ``exc`` and let this classify, or pass ``kind`` explicitly when the
    caller already knows (e.g. a provider payload with an ``errors`` array).
    """
    try:
        if status is None:
            status = status_of(exc)
        text = detail or (f"{type(exc).__name__}: {exc}" if exc is not None else "")
        resolved_kind = kind or classify_external_api_failure(status, text, error_class)
        svc = service or service_name()
        logger.warning(
            "%s provider=%s operation=%s kind=%s status=%s service=%s detail=%s",
            LOG_TOKEN,
            provider or "unknown",
            operation or "unknown",
            resolved_kind,
            status if status is not None else "-",
            svc,
            text[:300].replace("\n", " "),
        )
        if _EXTERNAL_API_FAILURE_TOTAL is not None:
            _EXTERNAL_API_FAILURE_TOTAL.labels(
                service=svc, provider=provider or "unknown", kind=resolved_kind
            ).inc()
    except Exception as emit_exc:  # the emitter must never break a request
        logger.debug("external_api_failure_emit failed: %s", emit_exc)
