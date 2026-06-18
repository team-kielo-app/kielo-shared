package errors

// BFF-namespace codes — emitted by kielo-mobile-bff when failures
// happen at the BFF layer itself (not pass-through from upstream).
// Pre-DDDDD declared at
// kielo-mobile-bff/internal/utils/typed_handlers.go:28-30
// (3 constants) — Sweep ZZZZ.
//
// Sweep DDDDD: centralizes the constants here so any future BFF
// fork (e.g. a kielo-admin-bff that emits the same shapes) can
// reuse the vocabulary. The 3 producer sites in typed_handlers.go
// become aliases pointing at these constants.
//
// Wire shape — same canonical envelope as AUTH_* codes:
//
//	{"error": {"code": "BFF_BACKEND_UNAVAILABLE",
//	           "message": "The service is temporarily unavailable...",
//	           "trace_id": "..."}, "message": "..."}
const (
	// CodeBFFInvalidRequestBody is emitted on bind/validation failure
	// at the BFF layer (e.g. malformed JSON on a POST). Stable English
	// message; mobile localizes via its BFF_* mapping in authErrors.ts
	// (queued for the next mobile codegen).
	CodeBFFInvalidRequestBody Code = "BFF_INVALID_REQUEST_BODY"

	// CodeBFFBackendUnavailable is emitted on transport failure to
	// an upstream service (connection refused, DNS, timeout). HTTP
	// 502 Bad Gateway.
	CodeBFFBackendUnavailable Code = "BFF_BACKEND_UNAVAILABLE"

	// CodeBFFBackendError is emitted on marshal / prepare-request
	// failures at the BFF layer — internal infra issues that don't
	// reach the upstream. HTTP 500.
	CodeBFFBackendError Code = "BFF_BACKEND_ERROR"
)
