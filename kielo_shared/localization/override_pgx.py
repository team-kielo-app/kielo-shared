"""asyncpg-backed implementation of OverrideStore.

Mirror of the Go side at ``kielo-shared/localization/overridepgx``.
Reads admin-approved translations from ``localization.dynamic_translations``
with the same status + source_version semantics:

* status='override' beats status='approved' (admin edit wins).
* stale source_version is silently filtered server-side; the seam falls
  through to the cache + provider chain.
* All other statuses (machine, pending_review) are misses.

Lives alongside the rest of the package because asyncpg is a soft
dependency of the localization stack — Phase 3.5b wires this for
kielolearn-engine and kielo-communications-service. Services that don't
need DB-backed overrides import ``NoopOverrideStore`` or
``MapOverrideStore`` from seam.py instead.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Protocol


logger = logging.getLogger(__name__)


# A minimal Protocol matching the parts of asyncpg.Pool that PgxOverrideStore
# uses. Lets tests inject a fake pool without spinning up real asyncpg.
#
# Sweep AAAAA: extended with `fetch` for the new batch_lookup method.
# `fetch` returns `list[asyncpg.Record]` (or list[dict] in fake impls)
# — anything indexable by column name via `row["column_name"]`.
class _Acquirer(Protocol):
    async def fetchval(self, query: str, *args: Any) -> Any: ...

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...


class PgxOverrideStore:
    """asyncpg-backed OverrideStore. Construct with an asyncpg.Pool.

    The same instance is safe across coroutines — asyncpg pools handle
    concurrency. One-query lookup; no caching at this layer (the Seam
    owns caching).
    """

    # Matches the SQL the Go-side adapter uses. The ORDER BY ranks
    # 'override' above 'approved' so an admin edit wins when both
    # exist (shouldn't happen given the unique constraint, but the
    # rank makes the intent explicit).
    _LOOKUP_QUERY = """
        SELECT translated_text
          FROM localization.dynamic_translations
         WHERE resource_type   = $1
           AND resource_id     = $2
           AND source_version  = $3
           AND language_code   = $4
           AND status         IN ('override', 'approved')
         ORDER BY CASE status WHEN 'override' THEN 0 ELSE 1 END
         LIMIT 1
    """

    def __init__(self, pool: _Acquirer | None) -> None:
        self._pool = pool

    async def lookup(
        self,
        namespace: str,
        source_id: str,
        source_version: str,
        target_locale: str,
    ) -> Optional[str]:
        """Return the override string, or None when:

        * no matching approved/override row exists for this (namespace,
          source_id, source_version, target_locale) tuple,
        * the pool is unconfigured (degrade gracefully so seam call
          sites that haven't wired the DB still work),
        * any asyncpg error fires (degrade rather than propagate; the
          seam's metrics will record the resolution path actually used
          by the provider chain).
        """
        if self._pool is None:
            return None

        try:
            value = await self._pool.fetchval(
                self._LOOKUP_QUERY,
                namespace,
                source_id,
                source_version,
                target_locale,
            )
        except Exception:
            logger.exception(
                "PgxOverrideStore.lookup failed",
                extra={
                    "namespace": namespace,
                    "source_id": source_id,
                    "target_locale": target_locale,
                },
            )
            return None

        if value is None:
            return None
        return str(value)

    # ─────────── Sweep AAAAA: batch lookup (BatchOverrideStore) ──────────

    # Composite-tuple SQL mirroring the Go side at
    # kielo-shared/localization/overridepgx/store.go:132-181.
    # Param shape: $1 = target_locale; ($2,$3,$4) = first (ns, id, ver)
    # tuple; ($5,$6,$7) = second; ... 1 + 3N total params.
    # pgx/asyncpg cap at 65535 PG params → headroom is huge for any
    # realistic batch size (N <= 21800).
    _BATCH_LOOKUP_HEAD = (
        "SELECT resource_type, resource_id, source_version, "
        "       translated_text, status "
        "  FROM localization.dynamic_translations "
        " WHERE language_code = $1 "
        "   AND status IN ('override', 'approved') "
        "   AND (resource_type, resource_id, source_version) IN ("
    )
    _BATCH_LOOKUP_TAIL = (
        ") "
        " ORDER BY resource_type, resource_id, source_version, "
        "          CASE status WHEN 'override' THEN 0 ELSE 1 END"
    )

    async def batch_lookup(
        self,
        refs: list[Any],  # list[OverrideRef] — typed Any to avoid import cycle
        target_locale: str,
    ) -> dict[str, str]:
        """Sweep AAAAA: 1 composite-tuple SQL query for N refs.

        Returns {override_batch_key(ns, id, ver): translated_text} for
        every hit. Misses omitted from the map. Mirrors Go
        ``overridepgx.Store.BatchLookup``.

        Degrades gracefully:
          - pool unconfigured       → empty dict
          - empty refs              → empty dict (no SQL issued)
          - any asyncpg exception   → empty dict, exception logged
        """
        out: dict[str, str] = {}
        if self._pool is None or not refs:
            return out

        # Lazy-import to avoid the cyclic import (seam.py imports from
        # override_pgx in the engine wiring; override_pgx importing
        # from seam.py would create a cycle at module-load time).
        from kielo_shared.localization.seam import override_batch_key

        placeholders: list[str] = []
        args: list[Any] = [target_locale]
        for i, ref in enumerate(refs):
            base = 2 + i * 3
            placeholders.append(f"(${base}, ${base + 1}, ${base + 2})")
            args.extend([ref.namespace, ref.source_id, ref.source_version])

        query = (
            self._BATCH_LOOKUP_HEAD
            + ", ".join(placeholders)
            + self._BATCH_LOOKUP_TAIL
        )

        try:
            records = await self._pool.fetch(query, *args)
        except Exception:
            logger.exception(
                "PgxOverrideStore.batch_lookup failed",
                extra={
                    "target_locale": target_locale,
                    "batch_size": len(refs),
                },
            )
            return out

        # ORDER BY puts 'override' before 'approved' for each
        # (ns, id, ver) triple; keep the first hit per key.
        for rec in records:
            key = override_batch_key(
                str(rec["resource_type"]),
                str(rec["resource_id"]),
                str(rec["source_version"]),
            )
            if key not in out:
                out[key] = str(rec["translated_text"])
        return out
