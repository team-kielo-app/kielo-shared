"""Canonical FastAPI error-envelope handlers."""

from __future__ import annotations

import http
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from kielo_shared import errors as kerrors
from kielo_shared.trace import current_trace_context

logger = logging.getLogger(__name__)


def _code_for_status(status_code: int) -> str:
    canonical = kerrors.default_for_status(status_code)
    if canonical != kerrors.CODE_GENERIC_ERROR:
        return canonical
    try:
        return http.HTTPStatus(status_code).name
    except ValueError:
        return f"HTTP_{status_code}"


def _envelope(
    code: str,
    message: str,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    trace = current_trace_context()
    if trace.trace_id:
        error["trace_id"] = trace.trace_id
    if trace.request_id:
        error["request_id"] = trace.request_id
    if extra:
        error.update(extra)
    return {"error": error, "message": message}


async def _http_exception_handler(
    _request: Request,
    exc: HTTPException,
) -> JSONResponse:
    detail = exc.detail
    extra: dict[str, Any] | None = None
    if isinstance(detail, dict) and "code" in detail and "message" in detail:
        code = str(detail["code"])
        message = str(detail["message"])
        extra = {
            key: value
            for key, value in detail.items()
            if key not in {"code", "message"}
        }
    else:
        code = _code_for_status(exc.status_code)
        message = str(detail) if detail is not None else code
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(code, message, extra=extra),
        headers=exc.headers,
    )


async def _validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    details = [
        {key: value for key, value in error.items() if key not in {"ctx", "url"}}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_envelope(
            kerrors.CODE_VALIDATION_FAILED,
            "Request validation failed",
            extra={"details": details},
        ),
    )


async def _unhandled_exception_handler(
    request: Request,
    _exc: Exception,
) -> JSONResponse:
    logger.exception("Unhandled exception in %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_envelope(kerrors.CODE_INTERNAL_ERROR, "Internal server error"),
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, _http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
    app.add_exception_handler(Exception, _unhandled_exception_handler)
