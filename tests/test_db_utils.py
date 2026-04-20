from kielo_shared import db_utils


def test_normalize_postgres_url_replaces_system_rootcert(monkeypatch):
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    url = "postgres://user:pass@example.com:5432/app?sslmode=verify-full&sslrootcert=system"

    normalized = db_utils.normalize_postgres_url(url)

    assert normalized.startswith("postgresql://")
    assert "sslrootcert=%2Ftmp%2Fca.pem" in normalized


def test_build_sync_sqlalchemy_url_and_connect_args_omits_options(monkeypatch):
    # search_path must NOT be sent via libpq's `options` startup parameter —
    # PgBouncer rejects "-c search_path=..." with
    # "unsupported startup parameter in options". Callers register the path
    # via register_search_path_listener instead.
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    url, connect_args = db_utils.build_sync_sqlalchemy_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app?sslmode=verify-full",
        db_utils.VECTOR_DB_SEARCH_PATH,
    )

    assert "sslrootcert=%2Ftmp%2Fca.pem" in url
    assert "options" not in connect_args


def test_build_asyncpg_url_and_connect_args_strips_ssl_query_params(monkeypatch):
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    async_url, connect_args = db_utils.build_asyncpg_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app?sslmode=verify-full&sslrootcert=system",
        db_utils.KLEARN_DB_SEARCH_PATH,
    )

    assert async_url.startswith("postgresql+asyncpg://user:pass@example.com:5432/app")
    # SQLAlchemy's asyncpg dialect prepared-statement cache must be off too.
    assert "prepared_statement_cache_size=0" in async_url
    # search_path must NOT be sent via asyncpg server_settings — it gets
    # rejected by PgBouncer/PlanetScale as an unsupported startup parameter.
    assert "server_settings" not in connect_args
    assert connect_args["ssl"] is not None
    # statement_cache_size must be 0 under PgBouncer transaction pooling —
    # cached prepared-statement plans become invalid when PgBouncer reassigns
    # the backend between transactions.
    assert connect_args["statement_cache_size"] == 0


def test_build_asyncpg_url_and_connect_args_sets_statement_cache_without_ssl():
    async_url, connect_args = db_utils.build_asyncpg_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app",
        db_utils.KLEARN_DB_SEARCH_PATH,
    )
    assert connect_args == {"statement_cache_size": 0}
    assert "prepared_statement_cache_size=0" in async_url


def test_build_asyncpg_url_respects_existing_prepared_statement_cache_size():
    async_url, _ = db_utils.build_asyncpg_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app?prepared_statement_cache_size=50",
        db_utils.KLEARN_DB_SEARCH_PATH,
    )
    # Do not stomp on an explicit caller-provided override.
    assert async_url.count("prepared_statement_cache_size=") == 1
    assert "prepared_statement_cache_size=50" in async_url


def test_register_asyncpg_disconnect_handler_patches_is_disconnect_and_adds_listener():
    import asyncpg
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(
        "postgresql+asyncpg://placeholder:placeholder@localhost/placeholder"
    )
    dialect = engine.sync_engine.dialect
    before = dialect.is_disconnect

    db_utils.register_asyncpg_disconnect_handler(engine)

    # (1) Dialect.is_disconnect must be replaced with our patched version.
    assert dialect.is_disconnect is not before

    # (2) Patched is_disconnect must recognise the production error.
    err = asyncpg.exceptions.InterfaceError(
        "cannot use Connection.transaction() in a manually started transaction"
    )
    assert dialect.is_disconnect(err, None, None) is True

    # Also: connection-closed variants.
    for msg in (
        "cannot perform operation: another operation is in progress",
        "cannot perform operation on closed connection",
        "connection is closed",
    ):
        assert dialect.is_disconnect(
            asyncpg.exceptions.InterfaceError(msg), None, None
        ) is True, f"should flag: {msg}"

    # Drill into __cause__ (SQLAlchemy wraps asyncpg errors).
    class Wrapped(Exception):
        pass

    inner = asyncpg.exceptions.InterfaceError(
        "cannot use Connection.transaction() in a manually started transaction"
    )
    outer = Wrapped("translated")
    outer.__cause__ = inner
    assert dialect.is_disconnect(outer, None, None) is True

    # Unrelated errors stay unaffected.
    assert dialect.is_disconnect(ValueError("nope"), None, None) is False
    assert dialect.is_disconnect(
        asyncpg.exceptions.InterfaceError("some other message"), None, None
    ) is False

    # (3) handle_error listener is registered for mid-statement errors.
    from sqlalchemy.event.registry import _key_to_collection

    events = {k[1] for k in _key_to_collection if k[0] == id(engine.sync_engine)}
    assert "handle_error" in events


def test_register_search_path_listener_rejects_bad_identifier():
    import pytest

    with pytest.raises(ValueError, match="Invalid search_path identifier"):
        db_utils._validate_search_path_idents("public; DROP TABLE users")


def _capture_listeners(engine, search_path):
    """Helper: swap `sqlalchemy.event.listens_for` to capture every listener
    registered by `register_search_path_listener`, then restore the original.
    """
    from sqlalchemy import event

    listeners: list = []

    def fake_listens_for(target, identifier, **kwargs):
        def decorator(fn):
            listeners.append((target, identifier, fn))
            return fn

        return decorator

    original = event.listens_for
    event.listens_for = fake_listens_for
    try:
        db_utils.register_search_path_listener(engine, search_path)
    finally:
        event.listens_for = original
    return listeners


def test_register_search_path_listener_sync_engine_uses_cursor():
    """Sync engines (no `sync_engine` attribute) keep running SET search_path
    through the standard DBAPI cursor — that path is safe for psycopg2/3.
    """

    # Use a tiny plain class so `hasattr(engine, 'sync_engine')` is False.
    class FakeSyncEngine:
        pass

    engine = FakeSyncEngine()
    listeners = _capture_listeners(engine, db_utils.KLEARN_DB_SEARCH_PATH)

    by_event = {identifier: (target, fn) for target, identifier, fn in listeners}
    assert set(by_event) == {"connect", "begin"}
    assert by_event["connect"][0] is engine
    assert by_event["begin"][0] is engine

    from unittest.mock import MagicMock

    dbapi_conn = MagicMock(spec=["cursor"])
    by_event["connect"][1](dbapi_conn, MagicMock())
    dbapi_conn.cursor.return_value.execute.assert_called_once_with(
        "SET search_path TO public,users,klearn,cms"
    )
    dbapi_conn.cursor.return_value.close.assert_called_once()

    sa_conn = MagicMock()
    by_event["begin"][1](sa_conn)
    sa_conn.exec_driver_sql.assert_called_once_with(
        "SET LOCAL search_path TO public,users,klearn,cms"
    )


def test_register_search_path_listener_async_engine_skips_connect_cursor_path():
    """Async engines should not execute search_path in the connect hook.

    We apply search_path via the SQLAlchemy ``begin`` event (SET LOCAL), which
    avoids asyncpg transaction-state edge cases during pool pre-ping.
    """

    class FakeAsyncEngine:
        def __init__(self):
            self.sync_engine = object()  # listener targets this

    class FakeAdapter:
        def cursor(self):
            raise AssertionError("async engine connect hook must not use cursor()")

    engine = FakeAsyncEngine()
    listeners = _capture_listeners(engine, db_utils.KLEARN_DB_SEARCH_PATH)
    by_event = {identifier: (target, fn) for target, identifier, fn in listeners}

    # Should no-op (and specifically must not call cursor()).
    by_event["connect"][1](FakeAdapter(), object())
