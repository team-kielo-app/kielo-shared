package middleware

import (
	"slices"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestDefaultCORSConfig_BaselineCannotBeShrunk(t *testing.T) {
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{})

	for _, h := range DefaultCORSAllowHeaders {
		if !slices.Contains(cfg.AllowHeaders, h) {
			t.Errorf("baseline header %q missing from AllowHeaders", h)
		}
	}
	for _, h := range DefaultCORSExposeHeaders {
		if !slices.Contains(cfg.ExposeHeaders, h) {
			t.Errorf("baseline expose header %q missing from ExposeHeaders", h)
		}
	}
	for _, m := range DefaultCORSAllowMethods {
		if !slices.Contains(cfg.AllowMethods, m) {
			t.Errorf("baseline method %q missing from AllowMethods", m)
		}
	}
	if !cfg.AllowCredentials {
		t.Error("AllowCredentials default should be true")
	}
	if cfg.MaxAge != 300 {
		t.Errorf("MaxAge default = %d, want 300", cfg.MaxAge)
	}
}

func TestDefaultCORSConfig_ExtraHeadersAppended(t *testing.T) {
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{
		ExtraAllowHeaders:  []string{"X-Upload-Token"},
		ExtraExposeHeaders: []string{"X-Job-Id"},
	})

	if !slices.Contains(cfg.AllowHeaders, "X-Upload-Token") {
		t.Error("extra allow header not appended")
	}
	if !slices.Contains(cfg.ExposeHeaders, "X-Job-Id") {
		t.Error("extra expose header not appended")
	}
	// Baseline still present
	if !slices.Contains(cfg.AllowHeaders, "X-Kielo-Learning-Language") {
		t.Error("baseline header dropped after extending")
	}
}

func TestDefaultCORSConfig_MethodOverride(t *testing.T) {
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{
		Methods: []string{echo.GET, echo.POST, echo.OPTIONS},
	})
	if slices.Contains(cfg.AllowMethods, echo.PATCH) {
		t.Error("Methods override should drop PATCH when not supplied")
	}
	if !slices.Contains(cfg.AllowMethods, echo.POST) {
		t.Error("Methods override must keep supplied verbs")
	}
}

func TestDefaultCORSConfig_AllowCredentialsExplicitFalse(t *testing.T) {
	f := false
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{
		AllowCredentials: &f,
	})
	if cfg.AllowCredentials {
		t.Error("AllowCredentials should be false when explicitly set")
	}
}

func TestDefaultCORSConfig_NegativeMaxAgeMeansZero(t *testing.T) {
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{MaxAge: -1})
	if cfg.MaxAge != 0 {
		t.Errorf("negative MaxAge should clamp to 0, got %d", cfg.MaxAge)
	}
}

func TestDefaultCORSConfig_CanonicalHeadersPresent(t *testing.T) {
	// These are the headers the ADR-006 wire contract names explicitly.
	// If any of them disappears from the baseline the contract is
	// broken and every service silently loses preflight support for them.
	must := []string{
		"Authorization",
		"Content-Type",
		"X-Internal-API-Key",
		"X-Kielo-Learning-Language",
		"X-Learning-Language",
		"X-Client-Trace-Id",
		"X-Request-Id",
		"Traceparent",
		"X-Device-Token",
		"X-Timezone-Offset-Minutes",
		"Accept-Language",
		"Idempotency-Key",
	}
	cfg := DefaultCORSConfig([]string{"https://example.com"}, CORSOptions{})
	for _, h := range must {
		if !slices.Contains(cfg.AllowHeaders, h) {
			t.Errorf("ADR-006 mandates header %q be in CORS baseline", h)
		}
	}
}
