// Package errors is the central source of truth for the Kielo
// monorepo's typed error codes per ADR-004 §5.
//
// Pre-DDDDD the canonical error envelope contract
// (`{"error": {"code", "message", "trace_id"}, "message": "..."}`)
// was implemented in kielo-shared/middleware/errors.go, but the
// code-value vocabulary was scattered across:
//
//   - kielo-shared/middleware/auth_codes.go    (11 AUTH_* codes, Sweep ZZZZ)
//   - kielo-auth-service/internal/handlers/error_codes.go (22 AUTH_* codes, Sweep ZZZZ)
//   - kielo-mobile-bff/internal/utils/typed_handlers.go (3 BFF_* codes, Sweep ZZZZ)
//   - kielo-convo/go_orchestrator/internal/api/errors.go (20 codes)
//   - kielo-media-upload-api/internal/handlers/errors.go (13 codes)
//   - 418 inline-literal `APIError(c, status, "CODE", ...)` call sites
//     across kielo-cms (364), kielo-mobile-bff (29), kielo-user-service
//     (19), kielo-content-service (6)
//
// Three near-identical struct definitions all implementing
// CodedHTTPError: AuthCodedError (kielo-shared), AuthErrorBody
// (kielo-auth-service), bffCodedError (kielo-mobile-bff).
//
// 27 distinct wire strings overlapped across services without a
// single source of truth. FEATURE_LIMIT_REACHED was the canonical
// drift example — emitted by 5 producer services with only 1 typed
// declaration.
//
// Sweep DDDDD ships this central package containing:
//
//   - defaults.go: the 9 structural defaults (BAD_REQUEST,
//     UNAUTHORIZED, etc.) that defaultCodeForStatus emits — now
//     exported as typed Code values rather than inline string
//     literals.
//
//   - auth.go: the 36 AUTH_* / AUTH_*_SENT / AUTH_*_DONE codes —
//     consolidating the prior 3-file split between middleware,
//     auth-service handlers, and the inline kielo-mobile-bff
//     references.
//
//   - coded.go: the unified CodedError struct + Coded(status, code,
//     message) constructor replacing 3 duplicated
//     {AuthCodedError, AuthErrorBody, bffCodedError} structs.
//
//   - feature_limit.go: FEATURE_LIMIT_REACHED + helpers — the
//     highest-fanout cross-service code.
//
//   - bff.go: BFF-namespace codes (kept in a separate file so the
//     kielo-mobile-bff alias surface is small).
//
// Migration discipline:
//
//   - Existing local typed constants (ErrCode*, AuthCode*, BFFCode*)
//     become aliases pointing at this package for 1 release cycle.
//   - The 418 inline-literal call sites migrate incrementally,
//     enforced by tests/contract/error_code_central_sot_test.go.
//   - Service-local domain codes (CMS_*, MEDIA_*, CONVO_*) stay
//     local with namespace prefix. This package is the home for
//     codes emitted by ≥ 2 services OR codes consumed by mobile /
//     admin clients via typed unions.
//
// Cross-language note: the Python sibling
// `kielolearn-engine/.../observability/error_envelope.py` derives
// codes from http.HTTPStatus(n).name which produces UNPROCESSABLE_ENTITY
// for 422 (vs Go VALIDATION_FAILED). A Python kielo_shared.errors
// mirror is queued for Sweep EEEEE; current papering-over via inline
// VALIDATION_FAILED literal at error_envelope.py:122 preserves
// behavior parity until then.
package errors
