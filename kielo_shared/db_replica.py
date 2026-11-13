"""A read-only replica route for reads that tolerate a few seconds of lag.

Same env contract as the Go `db.Reader`: off unless DB_REPLICA_READS is on
(1/true/on/yes); the replica is DATABASE_REPLICA_URL when set, otherwise the
primary DATABASE_URL on a PlanetScale host with the direct port (5432) and
"|replica" appended to the username. Any other host has no replica route.

There is no pooler in front of a replica, so every connection is a backend of
its own on a small machine: one connection per read, closed after it, at most
MAX_CONNECTIONS open in this process. Nothing is held between reads.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Optional

logger = logging.getLogger(__name__)

REPLICA_USER_SUFFIX = "|replica"
REPLICA_PORT = 5432
PLANETSCALE_HOST_SUFFIX = ".psdb.cloud"
MAX_CONNECTIONS = 1
CONNECT_TIMEOUT_S = 3.0
RETRY_AFTER_FAILURE_S = 60.0


def replica_reads_on() -> bool:
    return os.getenv("DB_REPLICA_READS", "").strip().lower() in (
        "1",
        "true",
        "on",
        "yes",
    )


def replica_url(primary_url: str) -> Optional[str]:
    explicit = (os.getenv("DATABASE_REPLICA_URL") or "").strip()
    if explicit:
        return explicit
    try:
        from sqlalchemy.engine import make_url

        url = make_url((primary_url or "").strip())
    except Exception:
        return None
    host = (url.host or "").lower()
    if not url.username or not host.endswith(PLANETSCALE_HOST_SUFFIX):
        return None
    username = url.username
    if not username.endswith(REPLICA_USER_SUFFIX):
        username += REPLICA_USER_SUFFIX
    return url.set(username=username, port=REPLICA_PORT).render_as_string(
        hide_password=False
    )


def _build_session_factory(url: str) -> Callable[[], Any]:
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.pool import NullPool

    from kielo_shared.db_utils import build_asyncpg_url_and_connect_args

    async_url, connect_args = build_asyncpg_url_and_connect_args(url, "public")
    # Prepared statements are cached per connection and the connection lives for
    # one read: caching only adds a round trip.
    connect_args["statement_cache_size"] = 0
    connect_args.pop("prepared_statement_name_func", None)
    connect_args["timeout"] = CONNECT_TIMEOUT_S
    parsed = make_url(async_url)
    parsed = parsed.set(query={**parsed.query, "prepared_statement_cache_size": "0"})
    engine = create_async_engine(parsed, poolclass=NullPool, connect_args=connect_args)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Replica:
    """One process's way to the replica. `usable()` says whether to try it;
    `session()` opens a bounded session; `mark_down()` sends reads back to the
    primary until the retry window passes."""

    def __init__(
        self,
        url: str,
        *,
        clock: Callable[[], float] = time.monotonic,
        factory_builder: Callable[[str], Callable[[], Any]] = _build_session_factory,
    ) -> None:
        self.url = url
        self._clock = clock
        self._factory_builder = factory_builder
        self._factory: Optional[Callable[[], Any]] = None
        self._gate: Optional[asyncio.Semaphore] = None
        self._down_until: Optional[float] = None
        self._announced_down = False

    def usable(self) -> bool:
        return self._down_until is None or self._clock() >= self._down_until

    def mark_down(self, exc: BaseException) -> None:
        if not self._announced_down:
            logger.warning(
                "DB_REPLICA_READS: replica read failed (%s); override prefetch"
                " uses the primary, replica retried in %.0f s",
                type(exc).__name__,
                RETRY_AFTER_FAILURE_S,
            )
            self._announced_down = True
        self._down_until = self._clock() + RETRY_AFTER_FAILURE_S

    def mark_up(self) -> None:
        if self._announced_down:
            logger.info("DB_REPLICA_READS: replica reads recovered")
        self._announced_down = False
        self._down_until = None

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Any]:
        if self._factory is None:
            self._factory = self._factory_builder(self.url)
        if self._gate is None:
            self._gate = asyncio.Semaphore(MAX_CONNECTIONS)
        async with self._gate:
            async with self._factory() as session:
                yield session


_process: Optional[Replica] = None
_process_resolved = False


def process_replica() -> Optional[Replica]:
    """The process's replica, or None when the switch is off or the database
    host has no replica route. Resolved once; a missing route is logged once."""
    global _process, _process_resolved
    if _process_resolved:
        return _process
    if not replica_reads_on():
        return None
    _process_resolved = True
    url = replica_url(os.getenv("DATABASE_URL", ""))
    if url is None:
        logger.info(
            "DB_REPLICA_READS is on but this database host has no replica route;"
            " override prefetch stays on the primary"
        )
        return None
    _process = Replica(url)
    return _process


def reset_process_replica() -> None:
    global _process, _process_resolved
    _process = None
    _process_resolved = False
