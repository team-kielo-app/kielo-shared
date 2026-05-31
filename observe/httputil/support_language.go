package httputil

import (
	"net/http"
	"strings"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// SupportLanguageQueryParam is the canonical query parameter name used
// to propagate the active support (UI/translation) language across HTTP
// hops between Kielo services. Mirrors the value pinned by
// `kielo-shared/middleware/support_language.go::SupportLanguageQueryParam`
// so producers + receivers share a single wire name.
const SupportLanguageQueryParam = "support_language_code"

// SupportLanguageHeader is the canonical service-to-service header
// carrying the active support language. Sibling to
// `LearningLanguageHeader` for learning language. Downstream Go
// services read it back via `middleware.ResolveSupportLanguageStateless`
// (which honors `support_language_code` query + Accept-Language); the
// Python engine FastAPI dependency
// `kielo_shared.locale.fastapi.get_support_language` reads the query
// + Accept-Language only. To stay Python-compatible, callers that
// also forward `Accept-Language` (which the per-service
// forwardCommonHeaders helpers already do) maintain end-to-end
// resolution even on hops that strip the X-Kielo-Support-Language
// header.
const SupportLanguageHeader = "X-Kielo-Support-Language"

// ApplySupportLanguageQuery copies the active support language from
// the request context onto the outbound HTTP request URL as a
// `support_language_code` query parameter. No-op when ctx has no
// support language (background jobs that haven't opted into per-
// request scoping) or when the param is already present (explicit
// caller overrides survive — admin tooling that deliberately inspects
// a different locale isn't clobbered).
//
// Sweep QQQQ canonical: every outbound HTTP client that talks to
// another Kielo service should consume this via the shared
// `PrepareInternalJSONRequest` helper (which calls it automatically)
// or, when crafting requests directly, invoke this + the header
// sibling. Pre-QQQQ only `kielo-content-service/internal/platform/
// klearn_client/client.go` (Sweep PPPP) and `kielo-mobile-bff/internal/
// utils/http.go::injectSupportLanguageQueryParam` implemented the same
// behavior per-client; QQQQ lifts the pattern into the shared helper
// so every service inherits it.
func ApplySupportLanguageQuery(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	q := req.URL.Query()
	if strings.TrimSpace(q.Get(SupportLanguageQueryParam)) != "" {
		return
	}
	code := sharedDB.SupportLanguageFromContext(req.Context())
	if code == "" {
		return
	}
	q.Set(SupportLanguageQueryParam, code)
	req.URL.RawQuery = q.Encode()
}

// ApplySupportLanguageHeader copies the active support language from
// the request context onto the outbound HTTP request as the canonical
// X-Kielo-Support-Language header. No-op when ctx has no support
// language or the header is already present.
//
// The header is the canonical service-to-service mechanism; the query
// param is the lower-precedence companion. Outbound clients should
// stamp both so the receiving service can resolve from either, even
// when a load balancer or proxy strips one of them.
func ApplySupportLanguageHeader(req *http.Request) {
	if req == nil {
		return
	}
	if strings.TrimSpace(req.Header.Get(SupportLanguageHeader)) != "" {
		return
	}
	code := sharedDB.SupportLanguageFromContext(req.Context())
	if code == "" {
		return
	}
	req.Header.Set(SupportLanguageHeader, code)
}
