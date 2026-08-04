"""Anti-orphan gates for English-keyed seeded copy.

``localization.dynamic_translations`` rows for the convo evaluation
fallbacks are keyed on ``resource_id = 'convo.evaluation_fallback.<english>'``
with ``source_version = source_version_from_text(english)``. That contract
has a silent failure mode: edit the English string in code (a copy sweep)
and every curated locale row stops matching — the runtime degrades to
English with no error anywhere. The 2026-08 sweep did exactly this to four
strings (repaired by V220).

Two live-Pg gates, following the ``test_localization_override_pgx``
conventions (``KIELO_TEST_PG_DSN``, skip-unless-reachable,
``KIELO_TEST_PG_REQUIRED=1`` turns the skip into a failure):

* every English-keyed row's embedded source still exists in the convo
  module's canonical ``_TRANSLATIONS`` dict (rows whose English vanished
  from code are orphans left by an un-migrated copy edit), and
* every such row's ``source_version`` equals the hash of the English
  embedded in its own resource_id (catches hand-authored re-key
  migrations with a wrong hash — em-dash/apostrophe byte traps).

Slug-keyed rows on the same surface (``…evaluation_fallback.drill.no_interaction``
etc.) don't embed their English source, so they are out of scope here —
the heuristic is "embedded tail contains a space ⇒ English-keyed".
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from kielo_shared.localization.seam import source_version_from_text

asyncpg = pytest.importorskip("asyncpg")

_PREFIX = "convo.evaluation_fallback."


def _dsn() -> str:
    return os.environ.get(
        "KIELO_TEST_PG_DSN",
        "postgres://kielo:password@localhost:5432/kielo_test",
    )


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


def _convo_canonical_strings() -> set[str]:
    """The canonical English strings from the convo agent's
    ``_TRANSLATIONS`` dict — the source of truth the DB rows key on."""
    module = (
        Path(__file__).resolve().parents[2]
        / "kielo-convo"
        / "python_agent"
        / "services"
        / "evaluation_fallbacks.py"
    )
    if not module.is_file():
        pytest.skip("kielo-convo checkout not present next to kielo-shared")
    text = module.read_text(encoding="utf-8")
    match = re.search(
        r"^_TRANSLATIONS[^=]*=\s*\{$(.*?)^\}$", text, re.M | re.S
    )
    assert match, "could not locate _TRANSLATIONS dict in evaluation_fallbacks.py"
    keys = set(re.findall(r'^    "((?:[^"\\]|\\.)+)": \{$', match.group(1), re.M))
    assert keys, "parsed zero canonical strings — the dict layout changed?"
    return keys


async def _english_keyed_rows(pool: Any) -> list[Any]:
    rows = await pool.fetch(
        """
        SELECT DISTINCT resource_id, source_version
        FROM localization.dynamic_translations
        WHERE resource_type = 'ui.string'
          AND resource_id LIKE $1
        """,
        _PREFIX + "%",
    )
    return [r for r in rows if " " in r["resource_id"][len(_PREFIX) :]]


@pytest.mark.asyncio
async def test_convo_fallback_rows_match_code_strings(real_pool: Any) -> None:
    canonical = _convo_canonical_strings()
    orphans = [
        row["resource_id"]
        for row in await _english_keyed_rows(real_pool)
        if row["resource_id"][len(_PREFIX) :] not in canonical
    ]
    assert not orphans, (
        "dynamic_translations rows keyed on English that no longer exists in "
        "evaluation_fallbacks.py — a copy edit shipped without a re-key "
        "migration (V220 pattern: re-seed at the new hash, delete the old "
        f"rows): {sorted(orphans)}"
    )


@pytest.mark.asyncio
async def test_convo_fallback_rows_hash_their_own_english(real_pool: Any) -> None:
    mismatches = [
        (row["resource_id"], row["source_version"])
        for row in await _english_keyed_rows(real_pool)
        if row["source_version"]
        != source_version_from_text(row["resource_id"][len(_PREFIX) :])
    ]
    assert not mismatches, (
        "rows whose source_version does not hash from the English embedded in "
        "their own resource_id — a re-key migration was authored with the "
        f"wrong bytes (watch em-dashes/apostrophes): {mismatches}"
    )


@pytest.mark.asyncio
async def test_convo_code_strings_keep_their_curated_locales(real_pool: Any) -> None:
    """The gate that would have caught the 2026-08 regression directly:
    every canonical code string that has EVER been curated must still have
    rows at its CURRENT hash. A string with zero rows anywhere is fine
    (autotranslate covers it); a string whose rows all sit at other
    resource_ids means the curation was orphaned by an English edit."""
    canonical = _convo_canonical_strings()
    seeded_ids = {
        row["resource_id"] for row in await _english_keyed_rows(real_pool)
    }
    if not seeded_ids:
        pytest.skip("no seeded evaluation-fallback rows in this database")
    missing = [
        english
        for english in sorted(canonical)
        if (_PREFIX + english) not in seeded_ids
    ]
    # Every seeded id maps back to code (test above); here we require the
    # inverse only when the surface is seeded at all: each code string
    # should have its curated rows. New strings added to code without a
    # seed WILL trip this — that is intentional: seed them (or curate via
    # admin) instead of silently shipping English-only.
    assert not missing, (
        "canonical strings with no curated rows at their current hash "
        f"(seed or re-key them): {missing}"
    )
