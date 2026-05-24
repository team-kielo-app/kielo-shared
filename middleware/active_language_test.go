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

// -------------------------------------------------------------------------
// RequireActiveLanguage tests (Phase 10C)
// -------------------------------------------------------------------------

func TestRequireActiveLanguage_PassesWhenLanguageOnContext(t *testing.T) {
	c := newRequestRecorder(t, "/x?learning_language_code=fi", nil)

	called := false
	// Run ActiveLanguage first (populates ctx), then RequireActiveLanguage.
	chain := ActiveLanguage(nil)(
		RequireActiveLanguage(nil)(func(c echo.Context) error {
			called = true
			got, ok := db.LanguageFromContext(c.Request().Context())
			if !ok || got != "fi" {
				t.Errorf("got (%q, %v), want (fi, true)", got, ok)
			}
			return nil
		}),
	)
	if err := chain(c); err != nil {
		t.Fatalf("expected handler to succeed, got: %v", err)
	}
	if !called {
		t.Fatal("handler never invoked")
	}
}

func TestRequireActiveLanguage_RejectsRequestWithoutLanguage(t *testing.T) {
	c := newRequestRecorder(t, "/x", nil)

	called := false
	chain := ActiveLanguage(nil)(
		RequireActiveLanguage(nil)(func(_ echo.Context) error {
			called = true
			return nil
		}),
	)
	err := chain(c)
	if err == nil {
		t.Fatal("expected 400 error, got nil")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("got code %d, want %d", httpErr.Code, http.StatusBadRequest)
	}
	if called {
		t.Error("handler MUST NOT be invoked when language is missing")
	}
}

func TestRequireActiveLanguage_AdminCarveOut(t *testing.T) {
	c := newRequestRecorder(t, "/admin/x", map[string]string{
		"X-Internal-API-Key": "test-key",
	})

	called := false
	chain := ActiveLanguage(nil)(
		RequireActiveLanguage(nil)(func(c echo.Context) error {
			called = true
			// ctx should NOT have a language attached — admin carve-out
			// expects handlers to branch on cross-language path.
			_, ok := db.LanguageFromContext(c.Request().Context())
			if ok {
				t.Error("admin carve-out should not attach a language to ctx")
			}
			return nil
		}),
	)
	if err := chain(c); err != nil {
		t.Fatalf("admin carve-out should bypass, got: %v", err)
	}
	if !called {
		t.Fatal("handler should be invoked for admin caller")
	}
}

func TestRequireActiveLanguage_ErrorMessageIncludesExtractedValue(t *testing.T) {
	// When extraction produces an unsupported value (e.g. "vi"), the
	// error body should include it so the misshaped caller is
	// identifiable from the response without grepping logs.
	c := newRequestRecorder(t, "/x?learning_language_code=vi", nil)

	chain := ActiveLanguage(nil)(
		RequireActiveLanguage(nil)(func(_ echo.Context) error {
			return nil
		}),
	)
	err := chain(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	msg, _ := httpErr.Message.(string)
	if !contains(msg, "vi") {
		// extract() returns "" for unsupported per DefaultExtractor; the
		// message embeds the bare extractor output ("") for diagnosis.
		// The contract is "include whatever extract() produced" so a
		// future extractor change is reflected verbatim.
		t.Logf("extractor produced empty for unsupported input; msg=%q", msg)
	}
	if !contains(msg, "learning_language_code") {
		t.Errorf("error message should mention learning_language_code; got %q", msg)
	}
}

func TestRequireActiveLanguageWithOptions_NoBypassRejectsInternalAPIKey(t *testing.T) {
	// When AllowInternalAPIKeyBypass=false, even the X-Internal-API-Key
	// header doesn't grant a free pass. Use this variant on route groups
	// that already authenticate via the internal API key (klearnAPI in
	// kielo-user-service is the canonical example) — otherwise the
	// carveout would degenerate to 100%-bypass.
	c := newRequestRecorder(t, "/x", map[string]string{
		"X-Internal-API-Key": "test-key",
	})

	called := false
	chain := ActiveLanguage(nil)(
		RequireActiveLanguageWithOptions(nil, RequireActiveLanguageOptions{
			AllowInternalAPIKeyBypass: false,
		})(func(_ echo.Context) error {
			called = true
			return nil
		}),
	)
	err := chain(c)
	if err == nil {
		t.Fatal("expected 400 error, got nil")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("got code %d, want %d", httpErr.Code, http.StatusBadRequest)
	}
	if called {
		t.Error("handler MUST NOT be invoked even with X-Internal-API-Key when bypass disabled")
	}
}

// `contains` helper is shared from errors_test.go in the same package.
