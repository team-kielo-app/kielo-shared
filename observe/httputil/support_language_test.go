package httputil

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

func TestApplySupportLanguageQuery_StampsFromCtx(t *testing.T) {
	t.Parallel()
	e := echo.New()
	req := httptest.NewRequest("GET", "/api/v3/foo", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetRequest(c.Request().WithContext(sharedDB.WithSupportLanguage(c.Request().Context(), "vi")))

	out := httptest.NewRequest("GET", "http://upstream/api/v3/bar", nil)
	out = out.WithContext(c.Request().Context())

	ApplySupportLanguageQuery(out)
	if got := out.URL.Query().Get(SupportLanguageQueryParam); got != "vi" {
		t.Fatalf("expected support_language_code=vi, got %q", got)
	}
}

func TestApplySupportLanguageQuery_PreservesExplicitCallerOverride(t *testing.T) {
	t.Parallel()
	out := httptest.NewRequest("GET", "http://upstream/api/v3/bar?support_language_code=sv", nil)
	out = out.WithContext(sharedDB.WithSupportLanguage(out.Context(), "vi"))

	ApplySupportLanguageQuery(out)
	if got := out.URL.Query().Get(SupportLanguageQueryParam); got != "sv" {
		t.Fatalf("expected caller override sv preserved, got %q", got)
	}
}

func TestApplySupportLanguageQuery_NoOpOnEmptyCtx(t *testing.T) {
	t.Parallel()
	out := httptest.NewRequest("GET", "http://upstream/api/v3/bar", nil)
	ApplySupportLanguageQuery(out)
	if got := out.URL.Query().Get(SupportLanguageQueryParam); got != "" {
		t.Fatalf("expected empty support_language_code, got %q", got)
	}
}

func TestApplySupportLanguageHeader_StampsFromCtx(t *testing.T) {
	t.Parallel()
	out := httptest.NewRequest("GET", "http://upstream/api/v3/bar", nil)
	out = out.WithContext(sharedDB.WithSupportLanguage(out.Context(), "vi"))

	ApplySupportLanguageHeader(out)
	if got := out.Header.Get(SupportLanguageHeader); got != "vi" {
		t.Fatalf("expected X-Kielo-Support-Language=vi, got %q", got)
	}
}

func TestApplySupportLanguageHeader_PreservesExplicitCallerOverride(t *testing.T) {
	t.Parallel()
	out := httptest.NewRequest("GET", "http://upstream/api/v3/bar", nil)
	out.Header.Set(SupportLanguageHeader, "sv")
	out = out.WithContext(sharedDB.WithSupportLanguage(out.Context(), "vi"))

	ApplySupportLanguageHeader(out)
	if got := out.Header.Get(SupportLanguageHeader); got != "sv" {
		t.Fatalf("expected caller override sv preserved, got %q", got)
	}
}
