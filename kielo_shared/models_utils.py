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
MODULE_OMORFI = "omorfi"
MODULE_VOIKKO = "voikko"

DEFAULT_HEALTH_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_WAIT_SECONDS = 30.0
DEFAULT_POLL_INTERVAL_SECONDS = 1.0

MODULE_SERVICE_ALIASES = {
    MODULE_WHISPER: ("kielo-models-whisper",),
    MODULE_EMBEDDINGS: ("kielo-models-embeddings",),
    MODULE_TRANSLATION_FI_EN: ("kielo-models-translation", "translation"),
    MODULE_TRANSLATION_EN_FI: ("kielo-models-translation", "translation"),
}

MODULE_HEALTH_PATHS = {
    MODULE_WHISPER: "health/modules/whisper",
    MODULE_EMBEDDINGS: "health/modules/embeddings",
    MODULE_TRANSLATION_FI_EN: "health/modules/translation_fi_en",
    MODULE_TRANSLATION_EN_FI: "health/modules/translation_en_fi",
    MODULE_OMORFI: "health/modules/omorfi",
    MODULE_VOIKKO: "health/modules/voikko",
}


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


def _module_status(
    payload: Mapping[str, Any] | None, module_name: str
) -> Mapping[str, Any] | None:
    modules = extract_modules(payload)
    names = (module_name, *MODULE_SERVICE_ALIASES.get(module_name, ()))
    for name in names:
        module = modules.get(name)
        if isinstance(module, Mapping):
            return module
    return None


def module_available(payload: Mapping[str, Any] | None, module_name: str) -> bool:
    module = _module_status(payload, module_name)
    if not isinstance(module, Mapping):
        return False
    return bool(module.get("available"))


def module_load_error(
    payload: Mapping[str, Any] | None, module_name: str
) -> str | None:
    module = _module_status(payload, module_name)
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


async def _fetch_module_health_async(
    base_url: str,
    module_name: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    path = MODULE_HEALTH_PATHS.get(module_name)
    if not path:
        return None
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            headers=_normalize_headers(headers),
        ) as client:
            response = await client.get(urljoin(base_url.strip().rstrip("/") + "/", path))
            payload = response.json()
        if response.status_code not in (200, 503) or not isinstance(payload, dict):
            return None
        return payload
    except Exception:
        return None


def _fetch_module_health(
    base_url: str,
    module_name: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    path = MODULE_HEALTH_PATHS.get(module_name)
    if not path:
        return None
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            headers=_normalize_headers(headers),
        ) as client:
            response = client.get(urljoin(base_url.strip().rstrip("/") + "/", path))
            payload = response.json()
        if response.status_code not in (200, 503) or not isinstance(payload, dict):
            return None
        return payload
    except Exception:
        return None


async def _fetch_missing_module_health_async(
    base_url: str,
    payload: Mapping[str, Any],
    required_modules: Sequence[str] | None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not required_modules:
        return dict(payload)
    module_payloads = [payload]
    for module_name in required_modules:
        if module_available(payload, module_name):
            continue
        module_payload = await _fetch_module_health_async(
            base_url,
            module_name,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )
        if module_payload:
            module_payloads.append(module_payload)
    return _merge_health_payloads(module_payloads)


def _fetch_missing_module_health(
    base_url: str,
    payload: Mapping[str, Any],
    required_modules: Sequence[str] | None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not required_modules:
        return dict(payload)
    module_payloads = [payload]
    for module_name in required_modules:
        if module_available(payload, module_name):
            continue
        module_payload = _fetch_module_health(
            base_url,
            module_name,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )
        if module_payload:
            module_payloads.append(module_payload)
    return _merge_health_payloads(module_payloads)


def _merge_health_payloads(
    payloads: Sequence[Mapping[str, Any] | None],
) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    modules: dict[str, Mapping[str, Any]] = {}
    for payload in payloads:
        if not isinstance(payload, Mapping):
            continue
        if not merged:
            merged = dict(payload)
        modules.update(extract_modules(payload))
    if modules:
        merged["modules"] = modules
    return merged


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
            payload = await _fetch_missing_module_health_async(
                base_url,
                payload,
                required_modules,
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
            payload = _fetch_missing_module_health(
                base_url,
                payload,
                required_modules,
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
            normalized_segments.append(
                {
                    "segment_index": int(item.get("segment_index", 0)),
                    "start_time": float(item.get("start_time", 0.0)),
                    "end_time": float(item.get("end_time", 0.0)),
                    "text_fi": str(item.get("text_fi") or ""),
                    "words": item.get("words") or [],
                    "words_array_fi": item.get("words_array_fi") or [],
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
