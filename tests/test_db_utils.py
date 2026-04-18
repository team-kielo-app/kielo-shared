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

    assert async_url == "postgresql+asyncpg://user:pass@example.com:5432/app"
    # search_path must NOT be sent via asyncpg server_settings — it gets
    # rejected by PgBouncer/PlanetScale as an unsupported startup parameter.
    assert "server_settings" not in connect_args
    assert connect_args["ssl"] is not None


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


def test_register_search_path_listener_async_engine_uses_raw_asyncpg():
    """Async engines hand the connect listener SQLAlchemy's asyncpg adapter.
    Going through `dbapi_connection.cursor()` on that adapter starts an
    implicit transaction it never closes, which eventually breaks
    `pool_pre_ping` under PgBouncer. The listener must bypass the adapter
    and talk to `driver_connection` (the raw asyncpg.Connection) instead.
    """
    import asyncio
    from unittest.mock import MagicMock

    class FakeAsyncEngine:
        def __init__(self):
            self.sync_engine = object()  # listener targets this

    executed: list[str] = []

    class FakeRawAsyncpgConn:
        async def execute(self, sql: str):
            executed.append(sql)
            return "OK"

    raw = FakeRawAsyncpgConn()

    class FakeAdapter:
        driver_connection = raw

        def cursor(self):
            raise AssertionError("async engine must not fall back to cursor()")

    engine = FakeAsyncEngine()
    listeners = _capture_listeners(engine, db_utils.KLEARN_DB_SEARCH_PATH)
    by_event = {identifier: (target, fn) for target, identifier, fn in listeners}

    # Call the connect listener. `await_only` inside the listener requires a
    # running greenlet spawn — easiest path is to invoke it from inside an
    # `asyncio.run(greenlet_spawn(...))` context.
    from sqlalchemy.util.concurrency import greenlet_spawn

    async def _drive():
        await greenlet_spawn(by_event["connect"][1], FakeAdapter(), MagicMock())

    asyncio.run(_drive())
    assert executed == ["SET search_path TO public,users,klearn,cms"]
