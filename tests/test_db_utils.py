from kielo_shared import db_utils


def test_normalize_postgres_url_replaces_system_rootcert(monkeypatch):
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    url = "postgres://user:pass@example.com:5432/app?sslmode=verify-full&sslrootcert=system"

    normalized = db_utils.normalize_postgres_url(url)

    assert normalized.startswith("postgresql://")
    assert "sslrootcert=%2Ftmp%2Fca.pem" in normalized


def test_build_sync_sqlalchemy_url_and_connect_args_sets_search_path(monkeypatch):
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    url, connect_args = db_utils.build_sync_sqlalchemy_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app?sslmode=verify-full",
        db_utils.VECTOR_DB_SEARCH_PATH,
    )

    assert "sslrootcert=%2Ftmp%2Fca.pem" in url
    assert connect_args == {"options": "-c search_path=cms,klearn,public"}


def test_build_asyncpg_url_and_connect_args_strips_ssl_query_params(monkeypatch):
    monkeypatch.setattr(db_utils, "resolve_ca_bundle_path", lambda: "/tmp/ca.pem")

    async_url, connect_args = db_utils.build_asyncpg_url_and_connect_args(
        "postgresql://user:pass@example.com:5432/app?sslmode=verify-full&sslrootcert=system",
        db_utils.KLEARN_DB_SEARCH_PATH,
    )

    assert async_url == "postgresql+asyncpg://user:pass@example.com:5432/app"
    assert connect_args["server_settings"]["search_path"] == "public,users,klearn,cms"
    assert connect_args["ssl"] is not None
