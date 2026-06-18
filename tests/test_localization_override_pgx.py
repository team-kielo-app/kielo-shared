"""Tests for kielo_shared.localization.override_pgx.

Two test classes:

* TestPgxOverrideStore_NoPg covers the degraded paths (nil pool, error
  swallowing) without requiring a postgres instance.
* TestPgxOverrideStore_RealPg exercises the SQL against the live
  kielo_test container if available; otherwise skipped (matches the
  Go-side `KIELO_TEST_PG_REQUIRED` convention).
"""

from __future__ import annotations

import os
import uuid
from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from kielo_shared.localization.override_pgx import PgxOverrideStore


def _dsn() -> str:
    return os.environ.get(
        "KIELO_TEST_PG_DSN",
        "postgres://kielo:password@localhost:5432/kielo_test",
    )


# ─── Degraded-path tests (no Pg) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_nil_pool_returns_none() -> None:
    store = PgxOverrideStore(None)
    got = await store.lookup("article.title", "id", "v1", "vi")
    assert got is None


class _RaisingPool:
    async def fetchval(self, query: str, *args: Any) -> Any:
        raise RuntimeError("simulated pg error")


@pytest.mark.asyncio
async def test_pool_error_returns_none_not_raises() -> None:
    store = PgxOverrideStore(_RaisingPool())
    got = await store.lookup("article.title", "id", "v1", "vi")
    assert got is None


class _CannedPool:
    def __init__(self, value: Any) -> None:
        self._value = value
        self.calls: list[tuple[Any, ...]] = []

    async def fetchval(self, query: str, *args: Any) -> Any:
        self.calls.append(args)
        return self._value


@pytest.mark.asyncio
async def test_canned_hit() -> None:
    pool = _CannedPool("Đặt cà phê")
    store = PgxOverrideStore(pool)
    got = await store.lookup("article.title", "id-1", "v1", "vi")
    assert got == "Đặt cà phê"
    assert pool.calls == [("article.title", "id-1", "v1", "vi")]


@pytest.mark.asyncio
async def test_canned_miss() -> None:
    store = PgxOverrideStore(_CannedPool(None))
    got = await store.lookup("article.title", "id", "v1", "vi")
    assert got is None


# ─── Real-Pg integration tests ────────────────────────────────────────────


# Skip the integration suite if asyncpg is missing or the test DB isn't
# reachable. CI may export KIELO_TEST_PG_REQUIRED=1 to turn the skip
# into a failure.
asyncpg = pytest.importorskip("asyncpg")


@pytest_asyncio.fixture
async def real_pool() -> AsyncIterator[Any]:
    try:
        pool = await asyncpg.create_pool(dsn=_dsn(), min_size=1, max_size=2)
    except Exception as exc:
        if os.environ.get("KIELO_TEST_PG_REQUIRED") == "1":
            pytest.fail(f"asyncpg.create_pool failed: {exc}")
        pytest.skip(f"postgres unreachable: {exc}")
    try:
        yield pool
    finally:
        await pool.close()


async def _seed(pool: Any, *, namespace: str, version: str, locale: str, value: str, status: str) -> str:
    resource_id = f"test-{uuid.uuid4()}"
    await pool.execute(
        """
        INSERT INTO localization.dynamic_translations
            (resource_type, resource_id, source_version, language_code,
             translated_text, status, source_locale, translator_source)
        VALUES ($1, $2, $3, $4, $5, $6, 'en', 'test')
        """,
        namespace, resource_id, version, locale, value, status,
    )
    return resource_id


async def _cleanup(pool: Any, namespace: str, resource_id: str) -> None:
    await pool.execute(
        "DELETE FROM localization.dynamic_translations "
        "WHERE resource_type=$1 AND resource_id=$2",
        namespace, resource_id,
    )


@pytest.mark.asyncio
async def test_approved_row_hit(real_pool: Any) -> None:
    rid = await _seed(real_pool,
                      namespace="article.title", version="v1", locale="vi",
                      value="Đặt cà phê", status="approved")
    try:
        store = PgxOverrideStore(real_pool)
        got = await store.lookup("article.title", rid, "v1", "vi")
        assert got == "Đặt cà phê"
    finally:
        await _cleanup(real_pool, "article.title", rid)


@pytest.mark.asyncio
async def test_override_beats_approved(real_pool: Any) -> None:
    # Same shape as the Go-side test: two rows, different versions
    # (sidesteps the unique constraint), confirm 'override' wins on v2.
    rid = f"test-{uuid.uuid4()}"
    try:
        for version, status, value in (
            ("v1", "approved", "approved-text"),
            ("v2", "override", "override-text"),
        ):
            await real_pool.execute(
                """
                INSERT INTO localization.dynamic_translations
                    (resource_type, resource_id, source_version, language_code,
                     translated_text, status, source_locale, translator_source)
                VALUES ('article.title', $1, $2, 'vi', $3, $4, 'en', 'test')
                """,
                rid, version, value, status,
            )

        store = PgxOverrideStore(real_pool)
        v1 = await store.lookup("article.title", rid, "v1", "vi")
        assert v1 == "approved-text"
        v2 = await store.lookup("article.title", rid, "v2", "vi")
        assert v2 == "override-text"
    finally:
        await _cleanup(real_pool, "article.title", rid)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["pending_review", "machine"])
async def test_non_serving_statuses_are_misses(real_pool: Any, status: str) -> None:
    rid = await _seed(real_pool,
                      namespace="article.title", version="v1", locale="vi",
                      value="placeholder", status=status)
    try:
        store = PgxOverrideStore(real_pool)
        got = await store.lookup("article.title", rid, "v1", "vi")
        assert got is None
    finally:
        await _cleanup(real_pool, "article.title", rid)


@pytest.mark.asyncio
async def test_stale_source_version_is_miss(real_pool: Any) -> None:
    rid = await _seed(real_pool,
                      namespace="article.title", version="v1", locale="vi",
                      value="v1-era text", status="approved")
    try:
        store = PgxOverrideStore(real_pool)
        # Row exists with v1; request asks for v2 — must miss.
        got = await store.lookup("article.title", rid, "v2", "vi")
        assert got is None
    finally:
        await _cleanup(real_pool, "article.title", rid)


@pytest.mark.asyncio
async def test_different_namespaces_isolated(real_pool: Any) -> None:
    rid_article = await _seed(real_pool,
                              namespace="article.title", version="v1", locale="vi",
                              value="Đặt cà phê", status="approved")
    rid_scenario = await _seed(real_pool,
                               namespace="scenario.title", version="v1", locale="vi",
                               value="Tình huống cà phê", status="approved")
    try:
        store = PgxOverrideStore(real_pool)
        assert await store.lookup("article.title", rid_article, "v1", "vi") == "Đặt cà phê"
        assert await store.lookup("scenario.title", rid_scenario, "v1", "vi") == "Tình huống cà phê"
        # Cross-namespace lookup must miss.
        assert await store.lookup("scenario.title", rid_article, "v1", "vi") is None
        assert await store.lookup("article.title", rid_scenario, "v1", "vi") is None
    finally:
        await _cleanup(real_pool, "article.title", rid_article)
        await _cleanup(real_pool, "scenario.title", rid_scenario)


# ─── Sweep AAAAA: batch_lookup tests ────────────────────────────────


class _CannedFetchPool:
    """Fake pool returning canned `fetch` results for batch_lookup."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records
        self.fetch_calls: list[tuple[str, tuple[Any, ...]]] = []

    async def fetchval(self, query: str, *args: Any) -> Any:
        return None

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        self.fetch_calls.append((query, args))
        return list(self._records)


@pytest.mark.asyncio
async def test_batch_lookup_nil_pool_returns_empty() -> None:
    from kielo_shared.localization import OverrideRef

    store = PgxOverrideStore(None)
    refs = [OverrideRef("ns", "s1", "v1"), OverrideRef("ns", "s2", "v1")]
    got = await store.batch_lookup(refs, "vi")
    assert got == {}


@pytest.mark.asyncio
async def test_batch_lookup_empty_refs_returns_empty() -> None:
    pool = _CannedFetchPool([])
    store = PgxOverrideStore(pool)
    got = await store.batch_lookup([], "vi")
    assert got == {}
    assert pool.fetch_calls == [], "no SQL should be issued for empty batch"


@pytest.mark.asyncio
async def test_batch_lookup_returns_one_call_with_composite_tuple() -> None:
    from kielo_shared.localization import OverrideRef, override_batch_key

    canned = [
        {
            "resource_type": "scenario.title",
            "resource_id": "s1",
            "source_version": "v1",
            "translated_text": "Vi tiêu đề một",
            "status": "approved",
        },
        {
            "resource_type": "scenario.title",
            "resource_id": "s3",
            "source_version": "v1",
            "translated_text": "Vi tiêu đề ba",
            "status": "override",
        },
    ]
    pool = _CannedFetchPool(canned)
    store = PgxOverrideStore(pool)
    refs = [
        OverrideRef("scenario.title", "s1", "v1"),
        OverrideRef("scenario.title", "s2", "v1"),  # miss
        OverrideRef("scenario.title", "s3", "v1"),
    ]
    got = await store.batch_lookup(refs, "vi")

    # ONE SQL call for the whole batch
    assert len(pool.fetch_calls) == 1
    query, args = pool.fetch_calls[0]
    # Composite-tuple shape: 1 + 3*N args
    assert args[0] == "vi"
    assert len(args) == 1 + 3 * 3  # target + 3 (ns, id, ver) tuples
    # Refs round-tripped in order
    assert args[1:4] == ("scenario.title", "s1", "v1")
    assert args[4:7] == ("scenario.title", "s2", "v1")
    assert args[7:10] == ("scenario.title", "s3", "v1")

    # Hits returned with correct packed keys; miss omitted
    assert got == {
        override_batch_key("scenario.title", "s1", "v1"): "Vi tiêu đề một",
        override_batch_key("scenario.title", "s3", "v1"): "Vi tiêu đề ba",
    }
    assert override_batch_key("scenario.title", "s2", "v1") not in got


@pytest.mark.asyncio
async def test_batch_lookup_pool_error_returns_empty_not_raises() -> None:
    """Same degrade-gracefully contract as single-row lookup."""
    from kielo_shared.localization import OverrideRef

    class _BrokenPool:
        async def fetchval(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("simulated")

        async def fetch(self, *args: Any, **kwargs: Any) -> list[Any]:
            raise RuntimeError("simulated")

    store = PgxOverrideStore(_BrokenPool())
    got = await store.batch_lookup([OverrideRef("ns", "s1", "v1")], "vi")
    assert got == {}


@pytest.mark.asyncio
async def test_batch_lookup_protocol_check_satisfies_batch_override_store() -> None:
    """Sweep AAAAA: the seam's runtime isinstance() check for
    BatchOverrideStore must succeed against PgxOverrideStore."""
    from kielo_shared.localization import BatchOverrideStore

    store = PgxOverrideStore(_CannedFetchPool([]))
    assert isinstance(store, BatchOverrideStore)
