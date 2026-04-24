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
    search_path: str | None = None,  # noqa: ARG001 - kept for backward compat
) -> tuple[str, dict[str, Any]]:
    """Build a sync SQLAlchemy URL and connect_args from a Postgres URL.

    NOTE: search_path is NOT sent via libpq's ``options`` startup parameter
    because connection proxies such as PgBouncer (used by PlanetScale Postgres)
    reject ``-c search_path=...`` with "unsupported startup parameter in options".
    Callers must register the search_path on the engine separately via
    :func:`register_search_path_listener`. The ``search_path`` parameter is
    kept in the signature for backward compatibility but is intentionally
    unused here.
    """
    return normalize_postgres_url(db_url), {}


def build_asyncpg_url_and_connect_args(
    db_url: str,
    search_path: str,  # noqa: ARG001 - kept for backward compat
) -> tuple[str, dict[str, Any]]:
    """Build an asyncpg URL and connect_args from a Postgres URL.

    NOTE: search_path is NOT sent via asyncpg's ``server_settings`` because
    connection proxies such as PgBouncer (used by PlanetScale Postgres) reject
    unrecognized startup parameters. Callers must register the search_path on
    the engine separately via :func:`register_search_path_listener`.
    The ``search_path`` parameter is kept in the signature for backward
    compatibility but is intentionally unused here.

    ``statement_cache_size`` is always set to ``0``. asyncpg's default
    behaviour is to keep a server-side prepared-statement plan keyed by
    statement id; under PgBouncer transaction pooling the backend connection
    can be reassigned between transactions, so the cached plan id is no
    longer valid and the next statement fails. Disabling the cache is the
    documented PlanetScale / PgBouncer configuration.
    """
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

    # SQLAlchemy's asyncpg dialect reads ``prepared_statement_cache_size`` from
    # the URL query string. Force it to 0: under PgBouncer transaction pooling
    # (PlanetScale) the dialect-level prepared-statement cache is keyed on
    # connections that can be reassigned between transactions, which corrupts
    # the cache. This is separate from asyncpg's own cache, disabled below via
    # ``connect_args["statement_cache_size"] = 0``; both must be off.
    if not any(
        k.lower() == "prepared_statement_cache_size" for k, _ in filtered_params
    ):
        filtered_params.append(("prepared_statement_cache_size", "0"))

    cleaned_query = urlencode(filtered_params)
    cleaned_url = urlunsplit(split_url._replace(query=cleaned_query))
    async_db_url = cleaned_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    cafile = sslrootcert if sslrootcert and os.path.exists(sslrootcert) else None

    connect_args: dict[str, Any] = {"statement_cache_size": 0}
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
    """Register search_path setup on an async engine, robust to transaction pooling.

    Replaces the previous approach of passing ``server_settings`` to asyncpg,
    which PgBouncer / PlanetScale (Neon) rejects as an unsupported startup
    parameter.

    Two listeners are registered to cover both deployment modes:

    * ``connect`` — for sync engines only, sets ``search_path`` at the
      session level via a DBAPI cursor.
    * ``begin`` — for all engines, fires at the start of every SQLAlchemy
      transaction and issues
      ``SET LOCAL search_path`` so the value applies for the lifetime of
      that transaction. This is required for PlanetScale / Neon / any
      PgBouncer-fronted Postgres that resets session state between
      transactions.

    Call once per engine, after
    :func:`sqlalchemy.ext.asyncio.create_async_engine`.
    """
    normalized = _validate_search_path_idents(search_path)
    is_async_engine = hasattr(engine, "sync_engine")
    sync_engine = engine.sync_engine if is_async_engine else engine

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection, _connection_record):  # noqa: ARG001
        if is_async_engine:
            return
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


_ASYNCPG_STATE_DISCONNECT_MARKERS = (
    # SQLAlchemy's asyncpg dialect `is_disconnect()` only checks for
    # "connection is closed". These additional asyncpg InterfaceError
    # shapes indicate the raw asyncpg connection has unrecoverable state
    # (transaction tracking desynced from the backend), which happens when
    # a prior `asyncpg.Transaction.rollback()` itself failed (network blip,
    # timeout, server-side reset) — it leaves `Connection._top_xact` set
    # while SQLAlchemy's wrapper resets `_started=False` and returns the
    # connection to the pool "clean". The next `pool_pre_ping` calls
    # `conn.transaction().start()` and fails.
    "cannot use Connection.transaction() in a manually started transaction",
    "cannot perform operation: another operation is in progress",
    "cannot perform operation on closed connection",
    "connection is closed",
)


def register_asyncpg_disconnect_handler(engine: Any) -> None:
    """Teach SQLAlchemy's pool and error-handling path to recognise asyncpg
    connection-state failures as disconnects, so the pool invalidates the
    bad connection instead of propagating the error to the caller.

    Two integration points are needed because SQLAlchemy routes errors
    differently depending on where they surface:

    1. ``is_disconnect()`` on the dialect — consulted by ``pool_pre_ping``
       during connection checkout. SQLAlchemy's built-in asyncpg matcher
       only recognises ``"connection is closed"`` and misses the
       transaction-state InterfaceError variants observed in production
       on PlanetScale / PgBouncer. We extend it on the engine's dialect
       instance (not the class) so only engines that opt in are affected.

    2. ``handle_error`` event listener — fires during statement execution.
       Covers the case where an InterfaceError surfaces *after* a
       connection has been successfully checked out (mid-query), so the
       pool still evicts the bad connection instead of returning it on
       the next checkout.

    Call once per async engine, after :func:`create_async_engine`.
    """
    try:
        import asyncpg
    except ImportError:
        return

    sync_engine = engine.sync_engine if hasattr(engine, "sync_engine") else engine
    dialect = sync_engine.dialect

    # --- (1) Extend dialect.is_disconnect for pool_pre_ping. ---
    _original_is_disconnect = dialect.is_disconnect

    def _is_disconnect(e, connection, cursor):
        if _original_is_disconnect(e, connection, cursor):
            return True
        # SQLAlchemy wraps asyncpg errors; check the exception itself plus
        # anything it wraps (``__cause__``) or originated from (``orig``).
        candidates = (e, getattr(e, "__cause__", None), getattr(e, "orig", None))
        for candidate in candidates:
            if isinstance(candidate, asyncpg.exceptions.InterfaceError):
                message = str(candidate)
                if any(
                    marker in message for marker in _ASYNCPG_STATE_DISCONNECT_MARKERS
                ):
                    return True
        return False

    dialect.is_disconnect = _is_disconnect

    # --- (2) handle_error event for mid-statement InterfaceErrors. ---
    @event.listens_for(sync_engine, "handle_error")
    def _mark_asyncpg_disconnect(context):  # noqa: ANN001 - SQLAlchemy event type
        original = context.original_exception
        if original is None:
            return
        if isinstance(
            original,
            (
                asyncpg.exceptions.InterfaceError,
                asyncpg.exceptions.ConnectionDoesNotExistError,
                asyncpg.exceptions.ConnectionFailureError,
            ),
        ):
            context.is_disconnect = True
