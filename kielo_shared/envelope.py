"""kielo_shared.envelope: tolerant decoding of the v3 ``{"data": ...}`` envelope.

Per ADR-006, Kielo services wrap singleton JSON responses in a
``{"data": <body>}`` envelope (lists use ``{"items": [...], ...}``,
errors use ``{"error": ...}``). Every consumer that decodes a peer
service's JSON must tolerate BOTH the enveloped shape AND a bare body,
so the producer flip can land without lock-step deploys.

:func:`unwrap_envelope` is deliberately conservative: it unwraps ONLY a
dict whose sole key is ``data``. Any other shape — a list, a bare dict
carrying real top-level keys, a multi-key dict that happens to include
``data`` (e.g. ``{"items": [...], "data": ...}``), a scalar — passes
through untouched, so bare and list/error bodies keep decoding exactly
as before.

This is the single source of truth; per-service copies of this helper
were consolidated here (engine, web-ingest, ingest, convo, content_bridge).
"""

from __future__ import annotations

from typing import Any


def unwrap_envelope(payload: Any) -> Any:
    """Return the inner body of a ``{"data": ...}`` envelope, else the payload.

    Only a single-key dict whose sole key is ``"data"`` is unwrapped;
    every other value (lists, multi-key dicts, scalars) is returned as-is.
    """
    if isinstance(payload, dict) and set(payload.keys()) == {"data"}:
        return payload["data"]
    return payload
