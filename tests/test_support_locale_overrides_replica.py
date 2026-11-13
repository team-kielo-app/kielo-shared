"""The override prefetch reads from a replica when the service opts in."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from kielo_shared import db_replica
from kielo_shared.localization.support_locale_overrides import (
    clear_prefetch_cache,
    prefetch_overrides_for_locale,
)

ROWS = [("Learn", "sv1", "Opi")]


class _Row:
    def __init__(self, rid, sv, txt):
        self.resource_id, self.source_version, self.translated_text = rid, sv, txt


class _Result:
    def fetchall(self):
        return [_Row(*r) for r in ROWS]


class _Session:
    def __init__(self, name, log, fail=False):
        self.name, self.log, self.fail = name, log, fail

    async def execute(self, statement, params=None):
        if self.fail:
            raise ConnectionError("replica down")
        self.log.append((self.name, str(statement).strip().split()[0].upper()))
        return _Result()


def _factory(name, log, fail=False):
    @asynccontextmanager
    async def factory():
        yield _Session(name, log, fail)

    return factory


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    clear_prefetch_cache()
    db_replica.reset_process_replica()
    for name in ("DB_REPLICA_READS", "DATABASE_REPLICA_URL", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    yield
    clear_prefetch_cache()
    db_replica.reset_process_replica()


def _replica(log, fail=False, clock=None):
    return db_replica.Replica(
        "postgresql://r@replica:5432/db",
        clock=clock or _Clock(),
        factory_builder=lambda url: _factory("replica", log, fail),
    )


@pytest.mark.asyncio
async def test_off_uses_the_primary(monkeypatch):
    log = []
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@x.pg.psdb.cloud:6432/db")
    got = await prefetch_overrides_for_locale(_factory("primary", log), "sv")
    assert got == {"Learn": ("sv1", "Opi")}
    assert log == [("primary", "SELECT")]
    assert db_replica.process_replica() is None


@pytest.mark.asyncio
async def test_on_reads_the_replica_for_the_prefetch_only(monkeypatch):
    log = []
    monkeypatch.setenv("DB_REPLICA_READS", "on")
    monkeypatch.setenv("DATABASE_REPLICA_URL", "postgresql://r@replica:5432/db")
    replica = db_replica.process_replica()
    assert replica is not None
    replica._factory_builder = lambda url: _factory("replica", log)
    got = await prefetch_overrides_for_locale(_factory("primary", log), "sv")
    assert got == {"Learn": ("sv1", "Opi")}
    assert log == [("replica", "SELECT")]


@pytest.mark.asyncio
async def test_replica_failure_falls_back_to_the_primary_and_logs_once(caplog):
    log = []
    clock = _Clock()
    replica = _replica(log, fail=True, clock=clock)
    with caplog.at_level("WARNING", logger="kielo_shared.db_replica"):
        a = await prefetch_overrides_for_locale(
            _factory("primary", log), "sv", replica=replica
        )
        clear_prefetch_cache()
        b = await prefetch_overrides_for_locale(
            _factory("primary", log), "sv", replica=replica
        )
    assert a == b == {"Learn": ("sv1", "Opi")}
    assert log == [("primary", "SELECT"), ("primary", "SELECT")]
    assert len([r for r in caplog.records if "replica read failed" in r.message]) == 1
    assert not replica.usable()
    clock.now += db_replica.RETRY_AFTER_FAILURE_S + 1
    assert replica.usable()


@pytest.mark.asyncio
async def test_replica_only_ever_sees_selects():
    log = []
    replica = _replica(log)
    for locale in ("sv", "vi", "fi"):
        await prefetch_overrides_for_locale(
            _factory("primary", log), locale, replica=replica
        )
    assert log and all(name == "replica" and verb == "SELECT" for name, verb in log)


def test_replica_url_derivation(monkeypatch):
    url = db_replica.replica_url(
        "postgresql://svc:pw@x.pg.psdb.cloud:6432/kielo?sslmode=require"
    )
    assert url.startswith("postgresql://svc%7Creplica:pw@x.pg.psdb.cloud:5432/kielo")
    assert db_replica.replica_url("postgresql://u:p@localhost:5432/db") is None
    monkeypatch.setenv("DATABASE_REPLICA_URL", "postgresql://r:p@rep:5432/db")
    assert db_replica.replica_url("postgresql://u:p@localhost/db") == (
        "postgresql://r:p@rep:5432/db"
    )


def test_replica_switch_values(monkeypatch):
    for value, expected in (
        ("on", True),
        ("TRUE", True),
        ("1", True),
        ("off", False),
        ("", False),
    ):
        monkeypatch.setenv("DB_REPLICA_READS", value)
        assert db_replica.replica_reads_on() is expected


def test_real_factory_builds_without_connecting():
    pytest.importorskip("asyncpg")
    url = db_replica.replica_url(
        "postgresql://svc:pw@x.pg.psdb.cloud:6432/kielo?sslmode=require"
    )
    factory = db_replica._build_session_factory(url)
    engine = factory.kw["bind"]
    assert engine.url.port == 5432
    assert engine.url.username == "svc|replica"
    assert type(engine.pool).__name__ == "NullPool"
