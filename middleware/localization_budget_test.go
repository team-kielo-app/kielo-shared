package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/localization"
)

func TestLocalizationBudget_Echo_StampsHeaders(t *testing.T) {
	t.Parallel()
	e := echo.New()
	e.Use(LocalizationBudget())
	e.GET("/x", func(c echo.Context) error {
		localization.RecordBudget(c.Request().Context(), localization.BudgetKindRefResolved, 264)
		localization.RecordBudget(c.Request().Context(), localization.BudgetKindOverrideLookup, 1)
		localization.RecordBudget(c.Request().Context(), localization.BudgetKindCacheGet, 1)
		localization.RecordBudget(c.Request().Context(), localization.BudgetKindProviderCall, 1)
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get(HeaderKieloLocRefs); got != "264" {
		t.Fatalf("expected refs header = 264, got %q", got)
	}
	if got := rec.Header().Get(HeaderKieloLocOverrides); got != "1" {
		t.Fatalf("expected overrides header = 1, got %q", got)
	}
	if got := rec.Header().Get(HeaderKieloLocCacheGets); got != "1" {
		t.Fatalf("expected cachegets header = 1, got %q", got)
	}
	if got := rec.Header().Get(HeaderKieloLocProviders); got != "1" {
		t.Fatalf("expected providers header = 1, got %q", got)
	}
}

func TestLocalizationBudget_Stdlib_StampsHeaders(t *testing.T) {
	t.Parallel()
	h := LocalizationBudgetStdlib(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localization.RecordBudget(r.Context(), localization.BudgetKindRefResolved, 60)
		localization.RecordBudget(r.Context(), localization.BudgetKindProviderCall, 1)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get(HeaderKieloLocRefs); got != "60" {
		t.Fatalf("expected refs = 60, got %q", got)
	}
	if got := rec.Header().Get(HeaderKieloLocProviders); got != "1" {
		t.Fatalf("expected providers = 1, got %q", got)
	}
}

func TestLocalizationBudget_NoSeamCalls_ZeroHeaders(t *testing.T) {
	t.Parallel()
	e := echo.New()
	e.Use(LocalizationBudget())
	e.GET("/x", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	e.ServeHTTP(rec, req)
	if got := rec.Header().Get(HeaderKieloLocRefs); got != "0" {
		t.Fatalf("expected zero refs, got %q", got)
	}
}
