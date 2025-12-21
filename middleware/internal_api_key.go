package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const InternalAPIKeyHeader = "X-Internal-API-Key"

// InternalAPIKeyConfig controls internal API key authentication behavior.
type InternalAPIKeyConfig struct {
	ExpectedKey          string
	HeaderName           string
	AllowMissingExpected bool
	AllowPaths           []string
	AllowPathPrefixes    []string
	MissingExpectedStatus int
	MissingStatus         int
	InvalidStatus         int
}

// NewInternalAPIKeyConfig returns a config populated with default status codes.
func NewInternalAPIKeyConfig(expectedKey string) InternalAPIKeyConfig {
	return InternalAPIKeyConfig{
		ExpectedKey:          expectedKey,
		HeaderName:           InternalAPIKeyHeader,
		MissingExpectedStatus: http.StatusInternalServerError,
		MissingStatus:         http.StatusUnauthorized,
		InvalidStatus:         http.StatusUnauthorized,
	}
}

// InternalAPIKeyAuth enforces the internal API key for Echo handlers.
func InternalAPIKeyAuth(cfg InternalAPIKeyConfig) echo.MiddlewareFunc {
	normalized := normalizeInternalAPIKeyConfig(cfg)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if isInternalAPIKeyPathAllowed(c.Request().URL.Path, normalized) {
				return next(c)
			}
			if normalized.expectedKey == "" {
				if normalized.allowMissingExpected {
					return next(c)
				}
				return echo.NewHTTPError(normalized.missingExpectedStatus, "internal API key is not configured")
			}
			providedKey := strings.TrimSpace(c.Request().Header.Get(normalized.headerName))
			if providedKey == "" {
				return echo.NewHTTPError(normalized.missingStatus, "missing internal API key")
			}
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(normalized.expectedKey)) != 1 {
				return echo.NewHTTPError(normalized.invalidStatus, "invalid internal API key")
			}
			return next(c)
		}
	}
}

// InternalAPIKeyMiddleware enforces the internal API key for net/http handlers.
func InternalAPIKeyMiddleware(cfg InternalAPIKeyConfig) func(http.Handler) http.Handler {
	normalized := normalizeInternalAPIKeyConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isInternalAPIKeyPathAllowed(r.URL.Path, normalized) {
				next.ServeHTTP(w, r)
				return
			}
			if normalized.expectedKey == "" {
				if normalized.allowMissingExpected {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "internal API key is not configured", normalized.missingExpectedStatus)
				return
			}
			providedKey := strings.TrimSpace(r.Header.Get(normalized.headerName))
			if providedKey == "" {
				http.Error(w, "missing internal API key", normalized.missingStatus)
				return
			}
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(normalized.expectedKey)) != 1 {
				http.Error(w, "invalid internal API key", normalized.invalidStatus)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type internalAPIKeyConfig struct {
	expectedKey          string
	headerName           string
	allowMissingExpected bool
	allowPaths           map[string]struct{}
	allowPathPrefixes    []string
	missingExpectedStatus int
	missingStatus         int
	invalidStatus         int
}

func normalizeInternalAPIKeyConfig(cfg InternalAPIKeyConfig) internalAPIKeyConfig {
	headerName := strings.TrimSpace(cfg.HeaderName)
	if headerName == "" {
		headerName = InternalAPIKeyHeader
	}
	missingExpectedStatus := cfg.MissingExpectedStatus
	if missingExpectedStatus == 0 {
		missingExpectedStatus = http.StatusInternalServerError
	}
	missingStatus := cfg.MissingStatus
	if missingStatus == 0 {
		missingStatus = http.StatusUnauthorized
	}
	invalidStatus := cfg.InvalidStatus
	if invalidStatus == 0 {
		invalidStatus = http.StatusUnauthorized
	}
	allowPaths := make(map[string]struct{})
	for _, path := range cfg.AllowPaths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		allowPaths[trimmed] = struct{}{}
	}
	var allowPathPrefixes []string
	for _, prefix := range cfg.AllowPathPrefixes {
		trimmed := strings.TrimSpace(prefix)
		if trimmed == "" {
			continue
		}
		allowPathPrefixes = append(allowPathPrefixes, trimmed)
	}
	return internalAPIKeyConfig{
		expectedKey:          strings.TrimSpace(cfg.ExpectedKey),
		headerName:           headerName,
		allowMissingExpected: cfg.AllowMissingExpected,
		allowPaths:           allowPaths,
		allowPathPrefixes:    allowPathPrefixes,
		missingExpectedStatus: missingExpectedStatus,
		missingStatus:         missingStatus,
		invalidStatus:         invalidStatus,
	}
}

func isInternalAPIKeyPathAllowed(path string, cfg internalAPIKeyConfig) bool {
	if _, ok := cfg.allowPaths[path]; ok {
		return true
	}
	for _, prefix := range cfg.allowPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
