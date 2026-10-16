package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

func fuzzContext(query, acceptLanguage, activeHeader, legacyHeader string) (echo.Context, bool) {
	req, err := http.NewRequest(http.MethodGet, "http://svc.test/x", nil)
	if err != nil {
		return nil, false
	}
	req.URL.RawQuery = query
	req.Header.Set(AcceptLanguageHeader, acceptLanguage)
	req.Header.Set(ActiveLanguageHeader, activeHeader)
	req.Header.Set(LegacyActiveLanguageHeader, legacyHeader)
	return echo.New().NewContext(req, httptest.NewRecorder()), true
}

func FuzzLanguageResolution(f *testing.F) {
	f.Add("support_language_code=vi", "fi,en;q=0.8", "fi", "sv")
	f.Add("support_language_code=ars&learning_language_code=SV", "vi-VN", "", "")
	f.Add("support_language_code="+url.QueryEscape("fi; DROP TABLE x"), "*", "fi,sv", "'; --")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, query, accept, active, legacy string) {
		c, ok := fuzzContext(query, accept, active, legacy)
		if !ok {
			return
		}
		support := ResolveSupportLanguageStateless(c)
		if support == "" || !locale.IsSupportedSupportLanguage(support) || locale.BaseLocale(support) != support {
			t.Fatalf("support language %q is not a supported base code", support)
		}
		if lang := DefaultExtractor(c); lang != "" {
			if err := db.ValidateLearningLanguageIdent(lang); err != nil {
				t.Fatalf("active language %q reaches the search path unvalidated: %v", lang, err)
			}
		}
	})
}
