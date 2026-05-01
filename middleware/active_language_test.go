package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/db"
)

func newRequestRecorder(t *testing.T, target string, headers map[string]string) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestActiveLanguage_KieloHeaderWinsOverMobileAndQueryAndJWT(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=fi", map[string]string{
		ActiveLanguageHeader: "sv",
		MobileLanguageHeader: "vi",
	})
	c.Set(JWTClaimKey, "en")

	called := false
	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		called = true
		got, ok := db.LanguageFromContext(c.Request().Context())
		if !ok || got != "sv" {
			t.Errorf("got (%q,%v), want (\"sv\", true) — header should win", got, ok)
		}
		return nil
	})
	if err := handler(c); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !called {
		t.Fatal("handler was not invoked")
	}
}

func TestActiveLanguage_MobileHeaderUsedWhenKieloAbsent(t *testing.T) {
	// Mobile app sends X-Learning-Language (existing contract via
	// applyLanguageHeaders.ts). When kielo-canonical isn't present,
	// the mobile header wins over query param + JWT.
	c := newRequestRecorder(t, "/x?learning_language_code=fi", map[string]string{
		MobileLanguageHeader: "sv",
	})
	c.Set(JWTClaimKey, "vi")

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "sv" {
			t.Errorf("got %q, want sv (mobile header should win when kielo header absent)", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_QueryParamFallback(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=fi", nil)

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "fi" {
			t.Errorf("got %q, want fi", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_JWTClaimFallback(t *testing.T) {
	c := newRequestRecorder(t, "/x", nil)
	c.Set(JWTClaimKey, "sv-SE")

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "sv" {
			t.Errorf("got %q, want sv", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_UnsupportedLearningLanguageLeavesContextEmpty(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=vi", nil)

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		if _, ok := db.LanguageFromContext(c.Request().Context()); ok {
			t.Error("expected localization-only language to be ignored for active learning context")
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_NoSourceLeavesContextEmpty(t *testing.T) {
	c := newRequestRecorder(t, "/x", nil)

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		if _, ok := db.LanguageFromContext(c.Request().Context()); ok {
			t.Error("expected no language on context")
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_BadHeaderFallsThroughToNextSource(t *testing.T) {
	// Bad header should not poison the chain — the query param should win.
	c := newRequestRecorder(t, "/x?learning_language_code=sv", map[string]string{
		ActiveLanguageHeader: "ENGLISH; DROP",
	})

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "sv" {
			t.Errorf("got %q, want sv (header was bad, query should win)", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_AllSourcesBadLeavesContextEmpty(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=BAD", map[string]string{
		ActiveLanguageHeader: "english",
	})
	c.Set(JWTClaimKey, "english")

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		if _, ok := db.LanguageFromContext(c.Request().Context()); ok {
			t.Error("expected no language on context — every source was invalid")
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_CustomExtractor(t *testing.T) {
	c := newRequestRecorder(t, "/x", nil)

	extract := ActiveLanguageExtractor(func(_ echo.Context) string {
		return "fi"
	})
	handler := ActiveLanguage(extract)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "fi" {
			t.Errorf("got %q, want fi", got)
		}
		return nil
	})
	_ = handler(c)
}
