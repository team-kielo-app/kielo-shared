"""kielo_shared.middleware — cross-service Starlette/FastAPI middleware.

Pythonic siblings to the Echo middleware in `kielo-shared/middleware/*.go`.
Each module here mirrors the wire-shape decisions of the Go side so a
request crossing the Go/Python boundary sees the same response headers,
metric labels, and sunset/deprecation contract.

Currently exposes:
  * legacy_alias — Deprecation + LegacyAlias factories for marking v1
    routes (and v3 alias routes) with IETF Deprecation/Sunset/Link
    headers and incrementing the v1-sunset burn-down counters.
"""
from __future__ import annotations

from kielo_shared.middleware.legacy_alias import (
    DeprecationMiddleware,
    LegacyAliasMiddleware,
)

__all__ = [
    "DeprecationMiddleware",
    "LegacyAliasMiddleware",
]
