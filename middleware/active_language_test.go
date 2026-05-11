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

func TestActiveLanguage_QueryParamWinsOverJWT(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=fi", nil)
	c.Set(JWTClaimKey, "en")

	called := false
	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		called = true
		got, ok := db.LanguageFromContext(c.Request().Context())
		if !ok || got != "fi" {
			t.Errorf("got (%q,%v), want (\"fi\", true) — query param should win", got, ok)
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

func TestActiveLanguage_AllSourcesBadLeavesContextEmpty(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=BAD", nil)
	c.Set(JWTClaimKey, "english")

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		if _, ok := db.LanguageFromContext(c.Request().Context()); ok {
			t.Error("expected no language on context — every source was invalid")
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_HeaderResolvesWithoutQueryOrJWT(t *testing.T) {
	c := newRequestRecorder(t, "/x", map[string]string{
		ActiveLanguageHeader: "fi",
	})

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, ok := db.LanguageFromContext(c.Request().Context())
		if !ok || got != "fi" {
			t.Errorf("got (%q,%v), want (fi,true) — X-Kielo-Learning-Language should resolve", got, ok)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_QueryWinsOverHeader(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=sv", map[string]string{
		ActiveLanguageHeader: "fi",
	})

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "sv" {
			t.Errorf("got %q, want sv — explicit query param must win over header", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_HeaderWinsOverJWT(t *testing.T) {
	c := newRequestRecorder(t, "/x", map[string]string{
		ActiveLanguageHeader: "fi",
	})
	c.Set(JWTClaimKey, "sv")

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "fi" {
			t.Errorf("got %q, want fi — header should win over JWT (per-call > profile default)", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_LegacyHeaderResolves(t *testing.T) {
	c := newRequestRecorder(t, "/x", map[string]string{
		LegacyActiveLanguageHeader: "fi",
	})

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "fi" {
			t.Errorf("got %q, want fi — legacy X-Learning-Language should still resolve until M+12 sunset", got)
		}
		return nil
	})
	_ = handler(c)
}

func TestActiveLanguage_CanonicalHeaderWinsOverLegacy(t *testing.T) {
	c := newRequestRecorder(t, "/x", map[string]string{
		ActiveLanguageHeader:       "fi",
		LegacyActiveLanguageHeader: "sv",
	})

	handler := ActiveLanguage(nil)(func(c echo.Context) error {
		got, _ := db.LanguageFromContext(c.Request().Context())
		if got != "fi" {
			t.Errorf("got %q, want fi — canonical header must win over legacy", got)
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
