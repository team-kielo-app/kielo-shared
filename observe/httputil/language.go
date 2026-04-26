package httputil

import (
	"net/http"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// KieloLearningLanguageHeader is the kielo-canonical header name used to
// propagate the active learning language across HTTP hops between Kielo
// services. Downstream services with the ActiveLanguage middleware (or the
// kielolearn-engine equivalent) read this header to apply per-language
// search_path on their DB transactions.
const KieloLearningLanguageHeader = "X-Kielo-Learning-Language"

// ApplyActiveLanguageHeader copies the active learning language from the
// request context onto the outbound HTTP request as
// X-Kielo-Learning-Language. No-op when ctx has no language (background
// jobs that haven't opted into per-language scoping) or when the header
// is already present (explicit caller overrides survive — admin tooling
// that deliberately inspects cross-language data isn't clobbered).
//
// Use this from every outbound HTTP client that talks to another Kielo
// service. The previous pattern of duplicating this 5-line shim across
// every clients package is now unnecessary.
func ApplyActiveLanguageHeader(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header.Get(KieloLearningLanguageHeader) != "" {
		return
	}
	if lang, ok := sharedDB.LanguageFromContext(req.Context()); ok {
		req.Header.Set(KieloLearningLanguageHeader, lang)
	}
}
