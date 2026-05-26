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
class _Acquirer(Protocol):
    async def fetchval(self, query: str, *args: Any) -> Any: ...


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
