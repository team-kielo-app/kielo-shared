"""Shared database URL and search_path helpers."""

from __future__ import annotations

import contextvars
import os
import re
import ssl
from typing import Any, Callable, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import event

VECTOR_DB_SEARCH_PATH = "cms, klearn, public"
KLEARN_DB_SEARCH_PATH = "public, users, klearn, cms"

# Default per-language template for the M3 transition window.
#
# The per-language schemas (klearn_<lang>, cms_<lang>) come first so reads
# of partitioned tables resolve there. The legacy klearn / cms schemas
# stay on the path during M3-M5 because not every table is partitioned at
# once; once a table moves, the per-language entry shadows the legacy one
# automatically. After M6 cutover the legacy entries can be dropped.
#
# users / localization / communications / convo / media stay where they
# are (no _shared umbrella) — they're already cross-language by
# construction. public is last for pgvector and other extensions.
DEFAULT_PER_LANGUAGE_SEARCH_PATH_TEMPLATE = (
    "klearn_{lang}, cms_{lang}, klearn, cms, "
    "users, localization, communications, convo, media, public"
)

_SEARCH_PATH_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Stricter than the search_path identifier regex: internal language codes are
# lowercase ISO 639-1/639-3 base codes (e.g. "fi", "sv", "zh"). Used by the
# per-language resolver before formatting it into a schema name.
_LANGUAGE_IDENT_RE = re.compile(r"^[a-z]{2,3}$")

SearchPathResolver = Callable[[], str]
SearchPathSpec = Union[str, SearchPathResolver]

# Per-request active language. Apps set this via middleware (FastAPI
# dependency, Starlette middleware, or a manual `set_active_language()`
# in background workers) before any DB transaction begins. Resolvers
# returned by `make_per_language_search_path` read it on every
# transaction `begin` event.
_active_language: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "kielo_active_language", default=None
)


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


def is_valid_language_ident(lang: str) -> bool:
    """Non-raising check for whether ``lang`` matches the language regex.

    Use from places (e.g. request middleware) that need to test a value
    without raising — those callers typically fall through to the next
    fallback source when the value fails. Fails-loud callers should use
    :func:`_validate_language_ident` directly.
    """
    return bool(lang) and bool(_LANGUAGE_IDENT_RE.match(lang))


def _validate_language_ident(lang: str) -> str:
    """Reject anything that isn't a recognisable language code.

    The result is interpolated into a schema name (e.g. ``klearn_fi``);
    looser identifier rules would let arbitrary identifiers through.
    """
    if not is_valid_language_ident(lang):
        raise ValueError(
            f"Invalid language identifier: {lang!r}. "
            f"Expected ISO 639 lowercase base code (e.g. 'fi', 'sv', 'zh')."
        )
    return lang


def set_active_language(lang: str) -> contextvars.Token[str | None]:
    """Set the active language for the current async/sync context.

    Returns a token that callers can pass to :func:`reset_active_language`
    if they want to restore the previous value (Starlette/FastAPI request
    middleware should not need to — the contextvar is implicitly per-task).
    Raises ``ValueError`` if ``lang`` doesn't match the language identifier
    regex, so bad inputs fail loud at the boundary.
    """
    return _active_language.set(_validate_language_ident(lang))


def reset_active_language(token: contextvars.Token[str | None]) -> None:
    _active_language.reset(token)


def get_active_language() -> str | None:
    """Return the active language for the current context, or ``None`` if unset."""
    return _active_language.get()


def make_per_language_search_path(
    template: str = DEFAULT_PER_LANGUAGE_SEARCH_PATH_TEMPLATE,
    fallback: str | None = None,
) -> SearchPathResolver:
    """Build a resolver suitable for :func:`register_search_path_listener`.

    The resolver reads :func:`get_active_language` on every call. If a
    language is set, it formats ``template`` with ``{lang}`` substituted
    and returns the result. If unset:

    * with ``fallback`` provided — return that string (useful for
      background workers that operate only on ``_shared`` data).
    * without ``fallback`` — raise ``RuntimeError``. This is the safe
      default: a transaction that hits the DB without a language scope
      would otherwise silently inherit the previous transaction's path
      under PgBouncer reuse, which is exactly the contamination
      footgun schema-per-language is designed to prevent.

    The resolver's output is validated by ``_validate_search_path_idents``
    inside the begin listener, so a malformed template fails the
    transaction rather than the DB.
    """

    def resolver() -> str:
        lang = _active_language.get()
        if lang is None:
            if fallback is not None:
                return fallback
            raise RuntimeError(
                "Active language is not set on this context. Either set it via "
                "kielo_shared.db_utils.set_active_language() before opening a "
                "DB transaction, or build the resolver with a fallback string "
                "(e.g. '_shared, public') for background workers that operate "
                "only on shared data."
            )
        # Defensive — we already validated on `set_active_language`, but a
        # caller could write directly to the contextvar.
        _validate_language_ident(lang)
        return template.format(lang=lang)

    return resolver


def register_search_path_listener(
    engine: Any,
    search_path: SearchPathSpec,
) -> None:
    """Register search_path setup on a SQLAlchemy engine, PgBouncer-safe.

    Replaces the previous approach of passing ``server_settings`` to
    asyncpg, which PgBouncer / PlanetScale (Neon) rejects as an unsupported
    startup parameter.

    ``search_path`` may be either:

    * **A string** — static path resolved once and applied at every
      transaction begin. Used by services that own a fixed schema set
      (e.g. ingest workers operating only on ``_shared`` content).
    * **A callable** — resolver invoked at every transaction begin.
      Used for per-request schema routing (schema-per-language). The
      resolver typically comes from :func:`make_per_language_search_path`
      and reads the active language from a contextvar set by per-request
      middleware. The resolved string is validated each call, so a
      malformed result fails the transaction rather than the DB.

    Two listeners are registered to cover both deployment modes:

    * ``connect`` — fires once at session establishment. For sync engines
      with a static path, sets ``SET search_path`` via a DBAPI cursor so
      pre-transaction operations also see the correct path. For async
      engines or callable paths, this is a no-op (callable paths can't
      be resolved at connect time because the language context isn't
      attached yet, and async engines apply the path at begin anyway).
    * ``begin`` — fires at the start of every SQLAlchemy transaction
      and issues ``SET LOCAL search_path`` so the value applies for the
      lifetime of that transaction. This is required for PlanetScale /
      Neon / any PgBouncer-fronted Postgres that resets session state
      between transactions.

    Call once per engine, after
    :func:`sqlalchemy.ext.asyncio.create_async_engine` or
    :func:`sqlalchemy.create_engine`.
    """
    is_callable = callable(search_path)
    static_normalized: str | None = None
    if not is_callable:
        # str → validate once eagerly so a typo fails at engine setup,
        # not at the first transaction.
        static_normalized = _validate_search_path_idents(search_path)  # type: ignore[arg-type]

    is_async_engine = hasattr(engine, "sync_engine")
    sync_engine = engine.sync_engine if is_async_engine else engine

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection, _connection_record):  # noqa: ARG001
        # Async engines apply search_path at begin; the connect hook would
        # require an awaitable cursor anyway.
        if is_async_engine:
            return
        # Callable paths depend on per-request context that isn't bound at
        # connect time. Skip; the begin hook handles it.
        if is_callable:
            return
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"SET search_path TO {static_normalized}")
        finally:
            cursor.close()

    @event.listens_for(sync_engine, "begin")
    def _on_begin(conn):
        if is_callable:
            resolved = _validate_search_path_idents(search_path())  # type: ignore[operator]
        else:
            resolved = static_normalized  # type: ignore[assignment]
        # SET LOCAL applies for the duration of the current transaction only,
        # so it survives PgBouncer reusing backends across transactions.
        conn.exec_driver_sql(f"SET LOCAL search_path TO {resolved}")


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
