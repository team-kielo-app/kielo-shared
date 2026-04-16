"""Shared database URL and search_path helpers."""

from __future__ import annotations

import os
import ssl
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VECTOR_DB_SEARCH_PATH = "cms, klearn, public"
KLEARN_DB_SEARCH_PATH = "public, users, klearn, cms"


def normalize_search_path(search_path: str) -> str:
    return ",".join(part.strip() for part in search_path.split(",") if part.strip())


def resolve_ca_bundle_path() -> str | None:
    candidates: list[str | None] = [
        os.getenv("SSL_CERT_FILE"),
        ssl.get_default_verify_paths().cafile,
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/usr/lib/ssl/cert.pem",
    ]

    try:
        import certifi

        candidates.append(certifi.where())
    except Exception:
        pass

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        normalized = candidate.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        if os.path.exists(normalized):
            return normalized

    return None


def _normalize_scheme(db_url: str) -> str:
    normalized = db_url.strip()
    if normalized.startswith("postgres://"):
        return normalized.replace("postgres://", "postgresql://", 1)
    return normalized


def normalize_postgres_url(db_url: str) -> str:
    normalized = _normalize_scheme(db_url)
    split_url = urlsplit(normalized)
    query_params = parse_qsl(split_url.query, keep_blank_values=True)

    sslmode = None
    sslrootcert = None
    filtered_params: list[tuple[str, str]] = []

    for key, value in query_params:
        key_lower = key.lower()
        if key_lower == "sslmode":
            sslmode = value
            filtered_params.append((key, value))
            continue
        if key_lower == "sslrootcert":
            sslrootcert = value
            continue
        filtered_params.append((key, value))

    resolved_ca_bundle = resolve_ca_bundle_path()
    if sslrootcert and sslrootcert.lower() != "system":
        filtered_params.append(("sslrootcert", sslrootcert))
    elif sslmode and sslmode.lower() == "verify-full" and resolved_ca_bundle:
        filtered_params.append(("sslrootcert", resolved_ca_bundle))

    cleaned_query = urlencode(filtered_params)
    return urlunsplit(split_url._replace(query=cleaned_query))


def build_sync_sqlalchemy_url_and_connect_args(
    db_url: str,
    search_path: str | None = None,
) -> tuple[str, dict[str, Any]]:
    connect_args: dict[str, Any] = {}
    if search_path:
        connect_args["options"] = f"-c search_path={normalize_search_path(search_path)}"
    return normalize_postgres_url(db_url), connect_args


def build_asyncpg_url_and_connect_args(
    db_url: str,
    search_path: str,
) -> tuple[str, dict[str, Any]]:
    normalized = normalize_postgres_url(db_url)
    split_url = urlsplit(normalized)
    query_params = parse_qsl(split_url.query, keep_blank_values=True)

    sslmode = None
    sslrootcert = None
    filtered_params: list[tuple[str, str]] = []

    for key, value in query_params:
        key_lower = key.lower()
        if key_lower == "sslmode":
            sslmode = value
            continue
        if key_lower == "sslrootcert":
            sslrootcert = value
            continue
        filtered_params.append((key, value))

    cleaned_query = urlencode(filtered_params)
    cleaned_url = urlunsplit(split_url._replace(query=cleaned_query))
    async_db_url = cleaned_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    cafile = sslrootcert if sslrootcert and os.path.exists(sslrootcert) else None

    connect_args: dict[str, Any] = {
        "server_settings": {"search_path": normalize_search_path(search_path)}
    }
    if sslmode:
        mode = sslmode.lower()
        if mode == "disable":
            connect_args["ssl"] = None
        elif mode in ("allow", "prefer", "require"):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connect_args["ssl"] = ssl_context
        elif mode in ("verify-ca", "verify_ca", "verifyca"):
            ssl_context = ssl.create_default_context(cafile=cafile)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            connect_args["ssl"] = ssl_context
        else:
            ssl_context = ssl.create_default_context(cafile=cafile)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            connect_args["ssl"] = ssl_context

    return async_db_url, connect_args
