package db

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvInt32 reads an environment variable as a positive int32, falling
// back to the supplied default when the var is unset, unparseable, or
// non-positive. Centralizes the pattern repeated across every Kielo
// service's connection-init code (PGX_MAX_CONNS, PGX_MIN_CONNS, etc.).
//
// Logs a WARN line when an explicit value is rejected so misconfiguration
// surfaces in service logs rather than silently degrading to defaults.
func EnvInt32(key string, fallback int32) int32 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || v <= 0 {
		log.Printf("WARN: invalid %s=%q, using default %d", key, raw, fallback)
		return fallback
	}
	return int32(v)
}

// EnvString returns the trimmed value of an environment variable, or the
// fallback when unset or empty-after-trim. Use for required-with-default
// strings (database URLs, project IDs, log levels) so trailing whitespace
// from misformatted .env files doesn't poison downstream parsers.
func EnvString(key, fallback string) string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	return raw
}

// EnvBool parses an environment variable as a boolean using
// strconv.ParseBool semantics (1/t/T/TRUE/true/True and 0/f/F/FALSE/false/False).
// Falls back when unset; logs WARN and returns fallback when set but
// unparseable so a misconfigured flag doesn't silently flip behavior.
func EnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("WARN: invalid %s=%q, using default %t", key, raw, fallback)
		return fallback
	}
	return v
}

// EnvDuration parses an environment variable as a time.Duration via
// time.ParseDuration ("30s", "5m", "1h"). Falls back when unset or
// non-positive; logs WARN when set but unparseable. Centralizes the
// timeout/interval pattern repeated across every Kielo service config.
func EnvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v <= 0 {
		log.Printf("WARN: invalid %s=%q, using default %s", key, raw, fallback)
		return fallback
	}
	return v
}
