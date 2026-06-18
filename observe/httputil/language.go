package httputil

import (
	"net/http"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// LearningLanguageQueryParam is the canonical query parameter name used to
// propagate the active learning language across HTTP hops between Kielo
// services. Downstream services with the ActiveLanguage middleware read
// this query param to apply per-language search_path on their DB
// transactions.
const LearningLanguageQueryParam = "learning_language_code"

// LearningLanguageHeader is the canonical service-to-service header
// (ADR-006 §3) carrying the active learning language. Downstream Go
// services read it via sharedmiddleware.ActiveLanguage; Python
// services read it via kielolearnengine's ActiveLanguageMiddleware.
// Always paired with the query param for defense-in-depth: downstream
// resolvers try the query first, then the header.
const LearningLanguageHeader = "X-Kielo-Learning-Language"

// ApplyActiveLanguageQuery copies the active learning language from the
// request context onto the outbound HTTP request URL as a
// `learning_language_code` query parameter. No-op when ctx has no
// language (background jobs that haven't opted into per-language
// scoping) or when the param is already present (explicit caller
// overrides survive — admin tooling that deliberately inspects
// cross-language data isn't clobbered).
//
// Use this from every outbound HTTP client that talks to another Kielo
// service. Pair with ApplyActiveLanguageHeader to additionally stamp
// the canonical header per ADR-006 §3.
func ApplyActiveLanguageQuery(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	q := req.URL.Query()
	if q.Get(LearningLanguageQueryParam) != "" {
		return
	}
	lang, ok := sharedDB.LanguageFromContext(req.Context())
	if !ok || lang == "" {
		return
	}
	q.Set(LearningLanguageQueryParam, lang)
	req.URL.RawQuery = q.Encode()
}

// ApplyActiveLanguageHeader copies the active learning language from
// the request context onto the outbound HTTP request as the canonical
// X-Kielo-Learning-Language header (ADR-006 §3). No-op when ctx has no
// language or the header is already present.
//
// The header is the canonical service-to-service mechanism; the query
// param is the lower-precedence companion. Outbound clients should
// stamp both so the receiving service can resolve from either, even
// when a load balancer or proxy strips one of them.
func ApplyActiveLanguageHeader(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header.Get(LearningLanguageHeader) != "" {
		return
	}
	lang, ok := sharedDB.LanguageFromContext(req.Context())
	if !ok || lang == "" {
		return
	}
	req.Header.Set(LearningLanguageHeader, lang)
}
