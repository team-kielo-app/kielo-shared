"""Shared database URL and search_path helpers."""

from __future__ import annotations

import os
import re
import ssl
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import event

VECTOR_DB_SEARCH_PATH = "cms, klearn, public"
KLEARN_DB_SEARCH_PATH = "public, users, klearn, cms"

_SEARCH_PATH_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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


def _validate_search_path_idents(search_path: str) -> str:
    """Reject anything that isn't a plain identifier list to prevent SQL injection
    (SET search_path can't be parameterized, so the value is interpolated).
    """
    normalized = normalize_search_path(search_path)
    for part in normalized.split(","):
        part = part.strip()
        if not _SEARCH_PATH_IDENT_RE.match(part):
            raise ValueError(
                f"Invalid search_path identifier: {part!r}. "
                f"Only [A-Za-z_][A-Za-z0-9_]* is allowed."
            )
    return normalized


def register_search_path_listener(engine: Any, search_path: str) -> None:
    """Register search_path setup on a SQLAlchemy engine, robust to transaction pooling.

    Two listeners are registered to cover both deployment modes:

    * ``connect`` — fires once per new asyncpg/psycopg2 connection. Sets
      ``search_path`` at the session level. Works for direct Postgres
      connections; harmless (immediately superseded by ``SET LOCAL``) for
      pooled deployments.
    * ``begin`` — fires at the start of every SQLAlchemy transaction. Issues
      ``SET LOCAL search_path`` so the value applies for the lifetime of
      that transaction. Required for PlanetScale / Neon / any
      PgBouncer-fronted Postgres that resets session state between
      transactions.

    Call once per engine, after :func:`sqlalchemy.ext.asyncio.create_async_engine`
    or :func:`sqlalchemy.create_engine`.
    """
    normalized = _validate_search_path_idents(search_path)
    sync_engine = getattr(engine, "sync_engine", engine)

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection, connection_record):  # noqa: ARG001
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"SET search_path TO {normalized}")
        finally:
            cursor.close()

    @event.listens_for(sync_engine, "begin")
    def _on_begin(conn):
        # SET LOCAL applies for the duration of the current transaction only,
        # so it survives PgBouncer reusing backends across transactions.
        conn.exec_driver_sql(f"SET LOCAL search_path TO {normalized}")
