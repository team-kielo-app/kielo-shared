"""kielo_shared.middleware — cross-service Starlette/FastAPI middleware.

Pythonic siblings to the Echo middleware in `kielo-shared/middleware/*.go`.
Each module here mirrors the wire-shape decisions of the Go side so a
request crossing the Go/Python boundary sees the same response headers,
metric labels, and sunset/deprecation contract.

Currently exposes:
  * legacy_alias — LegacyAlias factory for marking renamed v3 alias
    routes with IETF Deprecation/Sunset/Link headers + incrementing
    the v3-alias burn-down counter. (DeprecationMiddleware for v1
    sunset was retired alongside the Python v1 router itself —
    /klearn/api/v1 has zero remaining HTTP callers and the engine's
    /klearn/api/v3 surface is now the only mounted version.)
"""

from __future__ import annotations

from kielo_shared.middleware.legacy_alias import (
    LegacyAliasMiddleware,
)
from kielo_shared.middleware.support_locale_overrides import (
    SupportLocaleOverridesMiddleware,
)

__all__ = [
    "LegacyAliasMiddleware",
    "SupportLocaleOverridesMiddleware",
]
