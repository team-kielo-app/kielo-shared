package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

func newSupportCtx(t *testing.T, url string, headers map[string]string) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestResolveSupportLanguage_ExplicitQueryWins(t *testing.T) {
	c := newSupportCtx(t, "/x?support_language_code=fi", map[string]string{
		"Accept-Language": "vi",
	})

	got := ResolveSupportLanguageStateless(c)
	if got != "fi" {
		t.Errorf("got %q, want fi — explicit query must win", got)
	}
}

func TestResolveSupportLanguage_AcceptLanguageHeader(t *testing.T) {
	c := newSupportCtx(t, "/x", map[string]string{
		"Accept-Language": "vi-VN,vi;q=0.9,en;q=0.5",
	})

	got := ResolveSupportLanguageStateless(c)
	if got != "vi" {
		t.Errorf("got %q, want vi — Accept-Language should parse BCP47 and prefer vi", got)
	}
}

func TestResolveSupportLanguage_AcceptLanguagePicksSupportedOnly(t *testing.T) {
	// xh-ZA is not a supported support locale; the resolver must fall
	// through rather than returning the unsupported code.
	c := newSupportCtx(t, "/x", map[string]string{
		"Accept-Language": "xh-ZA",
	})

	got := ResolveSupportLanguageStateless(c)
	if got != locale.TierASupportLocale {
		t.Errorf("got %q, want default %q — unsupported Accept-Language should fall through", got, locale.TierASupportLocale)
	}
}

func TestResolveSupportLanguage_LearningLanguageContextFallback(t *testing.T) {
	c := newSupportCtx(t, "/x", nil)
	req := c.Request()
	c.SetRequest(req.WithContext(db.WithLanguage(req.Context(), "fi")))

	got := ResolveSupportLanguageStateless(c)
	if got != "fi" {
		t.Errorf("got %q, want fi — learning-language ctx should be used as support fallback", got)
	}
}

func TestResolveSupportLanguage_DefaultsToTierA(t *testing.T) {
	c := newSupportCtx(t, "/x", nil)

	got := ResolveSupportLanguageStateless(c)
	if got != locale.TierASupportLocale {
		t.Errorf("got %q, want %q — empty inputs should return tier-A default", got, locale.TierASupportLocale)
	}
}

func TestResolveSupportLanguage_QueryWinsOverContext(t *testing.T) {
	c := newSupportCtx(t, "/x?support_language_code=sv", nil)
	req := c.Request()
	c.SetRequest(req.WithContext(db.WithLanguage(req.Context(), "fi")))

	got := ResolveSupportLanguageStateless(c)
	if got != "sv" {
		t.Errorf("got %q, want sv — explicit query must win over learning-language ctx", got)
	}
}

func TestResolveSupportLanguage_HeaderWinsOverContext(t *testing.T) {
	c := newSupportCtx(t, "/x", map[string]string{
		"Accept-Language": "vi",
	})
	req := c.Request()
	c.SetRequest(req.WithContext(db.WithLanguage(req.Context(), "fi")))

	got := ResolveSupportLanguageStateless(c)
	if got != "vi" {
		t.Errorf("got %q, want vi — Accept-Language must win over learning-language ctx", got)
	}
}
