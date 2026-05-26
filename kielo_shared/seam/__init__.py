"""kielo_shared.seam — outbound vendor seams.

Mirror of `kielo-shared/seam/` in the Go tree. Each subpackage is a
narrow Provider interface + per-vendor impls + a metrics decorator
with bounded labels. Shared metric families
(`kielo_tts_*`, `kielo_llm_*`) match the Go side so cross-process
dashboards aggregate cleanly.
"""

from __future__ import annotations
