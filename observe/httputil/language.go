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

// ApplyActiveLanguageQuery copies the active learning language from the
// request context onto the outbound HTTP request URL as a
// `learning_language_code` query parameter. No-op when ctx has no
// language (background jobs that haven't opted into per-language
// scoping) or when the param is already present (explicit caller
// overrides survive — admin tooling that deliberately inspects
// cross-language data isn't clobbered).
//
// Use this from every outbound HTTP client that talks to another Kielo
// service.
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
