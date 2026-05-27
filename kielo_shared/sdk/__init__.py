"""Kielo backend Python SDK.

Re-exports generated pydantic models from `kielo_shared.sdk.v3.models`
so service-to-service callers can use typed responses + typed request
bodies for cross-service HTTP calls. Companion to the TypeScript
`@hey-api`-generated SDKs at `kielo-app/src/api/v3/` and
`kielo-admin-ui/src/api/v3/`.

Source of truth: `docs/api/v3/openapi-internal.json` (committed).
Regenerate with `make api-client-codegen-python`.

Consumers today:
  - kielolearn-engine: `kielolearn-engine/src/kielolearnengine/services/
    kielo_backend_client.py` and its 8 sibling clients call user-service,
    cms, and engine-internal routes; this SDK provides response shapes.
  - kielo-ingest-processor: `kielo-ingest-processor/src/kieloingestprocessor/
    clients/cms.py` calls cms internal routes for article ingestion.

Not consumed by:
  - Mobile/admin TypeScript clients — they use the `@hey-api` SDK at
    `kielo-{app,admin-ui}/src/api/v3/` generated from the smaller
    mobile/admin spec at `docs/api/v3/openapi.json`.
  - Go service-to-service callers — there's no Go SDK yet; the Go
    services consume each other through 712 `map[string]any` decode
    sites (per the v3 SDK adoption survey).
"""

from __future__ import annotations
