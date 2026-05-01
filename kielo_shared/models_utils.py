"""Shared helpers for Kielo models health and readiness checks."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urljoin

import httpx

MODULE_WHISPER = "whisper"
MODULE_EMBEDDINGS = "embeddings"
MODULE_TRANSLATION_FI_EN = "translation_fi_en"
MODULE_TRANSLATION_EN_FI = "translation_en_fi"
MODULE_TRANSLATION_SV_EN = "translation_sv_en"
MODULE_TRANSLATION_EN_SV = "translation_en_sv"
MODULE_TRANSLATION_EN_VI = "translation_en_vi"
MODULE_OMORFI = "omorfi"
MODULE_VOIKKO = "voikko"

DEFAULT_HEALTH_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_WAIT_SECONDS = 30.0
DEFAULT_POLL_INTERVAL_SECONDS = 1.0


def build_health_url(base_url: str) -> str:
    normalized = (base_url or "").strip().rstrip("/")
    if not normalized:
        raise RuntimeError("Models base URL is not configured.")
    return urljoin(normalized + "/", "health")


def extract_modules(payload: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if not isinstance(payload, Mapping):
        return {}
    modules = payload.get("modules")
    if not isinstance(modules, Mapping):
        return {}
    return {
        str(name): status
        for name, status in modules.items()
        if isinstance(status, Mapping)
    }


def module_available(payload: Mapping[str, Any] | None, module_name: str) -> bool:
    modules = extract_modules(payload)
    module = modules.get(module_name)
    if not isinstance(module, Mapping):
        return False
    return bool(module.get("available"))


def module_load_error(
    payload: Mapping[str, Any] | None, module_name: str
) -> str | None:
    modules = extract_modules(payload)
    module = modules.get(module_name)
    if not isinstance(module, Mapping):
        return None
    load_error = module.get("load_error")
    if load_error is None:
        return None
    return str(load_error)


def service_status(payload: Mapping[str, Any] | None) -> str:
    if not isinstance(payload, Mapping):
        return "unknown"
    value = payload.get("status")
    return str(value) if value is not None else "unknown"


def required_modules_ready(
    payload: Mapping[str, Any] | None,
    required_modules: Sequence[str] | None = None,
) -> bool:
    if required_modules:
        return all(
            module_available(payload, module_name) for module_name in required_modules
        )
    return service_status(payload) == "healthy"


def readiness_error_message(
    payload: Mapping[str, Any] | None,
    required_modules: Sequence[str] | None = None,
) -> str:
    if required_modules:
        problems: list[str] = []
        for module_name in required_modules:
            if module_available(payload, module_name):
                continue
            load_error = module_load_error(payload, module_name)
            if load_error:
                problems.append(f"{module_name}: {load_error}")
            else:
                problems.append(f"{module_name}: unavailable")
        if problems:
            return "; ".join(problems)
    status = service_status(payload)
    if status == "healthy":
        return ""
    return f"models service status is {status}"


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {str(key): str(value) for key, value in headers.items() if value is not None}


async def fetch_models_health_async(
    base_url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        headers=_normalize_headers(headers),
    ) as client:
        response = await client.get(build_health_url(base_url))
        payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"Models health endpoint returned an unexpected payload (status={response.status_code})."
        )
    if response.status_code not in (200, 503):
        raise RuntimeError(
            f"Models health endpoint returned status {response.status_code}."
        )
    return payload


def fetch_models_health(
    base_url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    with httpx.Client(
        timeout=timeout_seconds,
        headers=_normalize_headers(headers),
    ) as client:
        response = client.get(build_health_url(base_url))
        payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"Models health endpoint returned an unexpected payload (status={response.status_code})."
        )
    if response.status_code not in (200, 503):
        raise RuntimeError(
            f"Models health endpoint returned status {response.status_code}."
        )
    return payload


async def wait_for_required_modules_async(
    base_url: str,
    required_modules: Sequence[str] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
    max_wait_seconds: float = DEFAULT_MAX_WAIT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + max_wait_seconds
    last_error = "models health check did not complete"

    while True:
        try:
            payload = await fetch_models_health_async(
                base_url,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            if required_modules_ready(payload, required_modules):
                return payload
            last_error = readiness_error_message(payload, required_modules)
        except (
            Exception
        ) as exc:  # pragma: no cover - network/path errors are caller-specific
            last_error = str(exc)

        if time.monotonic() >= deadline:
            modules_text = ", ".join(required_modules or []) or "service readiness"
            raise RuntimeError(
                f"Timed out waiting for models readiness ({modules_text}): {last_error}"
            )

        await asyncio.sleep(poll_interval_seconds)


def wait_for_required_modules(
    base_url: str,
    required_modules: Sequence[str] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
    max_wait_seconds: float = DEFAULT_MAX_WAIT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + max_wait_seconds
    last_error = "models health check did not complete"

    while True:
        try:
            payload = fetch_models_health(
                base_url,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            if required_modules_ready(payload, required_modules):
                return payload
            last_error = readiness_error_message(payload, required_modules)
        except (
            Exception
        ) as exc:  # pragma: no cover - network/path errors are caller-specific
            last_error = str(exc)

        if time.monotonic() >= deadline:
            modules_text = ", ".join(required_modules or []) or "service readiness"
            raise RuntimeError(
                f"Timed out waiting for models readiness ({modules_text}): {last_error}"
            )

        time.sleep(poll_interval_seconds)


def modules_header(required_modules: Iterable[str]) -> str:
    return ", ".join(str(module_name) for module_name in required_modules)


def normalize_transcription_payload(
    payload: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise RuntimeError("Unexpected transcription response payload.")

    raw_segments = payload.get("segments")
    normalized_segments: list[dict[str, Any]] = []
    if isinstance(raw_segments, Sequence) and not isinstance(
        raw_segments, (str, bytes, bytearray)
    ):
        for item in raw_segments:
            if not isinstance(item, Mapping):
                continue
            # Accept both neutral keys (``text_primary`` / ``words_array``)
            # and legacy language-suffixed keys (``text_fi`` /
            # ``words_array_fi``) from upstream transcription payloads.
            # Emit BOTH the neutral shape (required by the updated
            # ``TranscriptionSegment`` model in ingest-processor) and the
            # legacy aliases (still read by kielolearn-engine's
            # transcription pipeline and older consumers).
            text_primary = str(
                item.get("text_primary") or item.get("text_fi") or ""
            )
            words_array = (
                item.get("words_array")
                if item.get("words_array") is not None
                else item.get("words_array_fi")
            ) or []
            normalized_segments.append(
                {
                    "segment_index": int(item.get("segment_index", 0)),
                    "start_time": float(item.get("start_time", 0.0)),
                    "end_time": float(item.get("end_time", 0.0)),
                    "text_primary": text_primary,
                    "text_fi": text_primary,
                    "words": item.get("words") or [],
                    "words_array": words_array,
                    "words_array_fi": words_array,
                }
            )

    try:
        language_probability = float(payload.get("language_probability") or 0.0)
    except (TypeError, ValueError):
        language_probability = 0.0

    audio_duration = payload.get("audio_duration")
    if audio_duration is not None:
        try:
            audio_duration = float(audio_duration)
        except (TypeError, ValueError):
            audio_duration = None

    return {
        "segments": normalized_segments,
        "language_probability": language_probability,
        "audio_duration": audio_duration,
    }
