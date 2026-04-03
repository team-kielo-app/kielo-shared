package gcs

import (
	"fmt"
	"os"
	"strings"
)

// BuildServeBaseURL returns a base URL for serving objects under a bucket/path prefix.
// It prefers an explicit CDN base, then a configured emulator host, and finally the public GCS URL.
func BuildServeBaseURL(bucket, pathPrefix, cdnBaseURL string) string {
	if bucket == "" {
		return ""
	}

	// Normalize prefix and ensure it ends with a trailing slash for concatenation.
	prefix := strings.Trim(pathPrefix, "/")
	if prefix != "" {
		prefix += "/"
	}

	// CDN overrides everything.
	if cdnBaseURL != "" {
		base := strings.TrimRight(cdnBaseURL, "/")
		return fmt.Sprintf("%s/%s", base, prefix)
	}

	// Emulator-aware path: http://host/storage/v1/b/<bucket>/o/<prefix>
	if emu := EmulatorHostFromEnv(); emu != "" {
		base := strings.TrimRight(emu, "/")
		base = strings.TrimSuffix(base, "/storage/v1")
		base = strings.TrimSuffix(base, "/storage")
		return fmt.Sprintf("%s/storage/v1/b/%s/o/%s", base, bucket, prefix)
	}

	// Default GCS public URL.
	return fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucket, prefix)
}

// EmulatorHostFromEnv normalizes the emulator host from environment variables using the same logic as LoadConfig.
func EmulatorHostFromEnv() string {
	raw := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST"))
	if raw == "" {
		return ""
	}
	// For external URL building, use HOST_IP if available
	if external := strings.TrimSpace(os.Getenv("HOST_IP")); external != "" {
		port := ParseEmulatorPort()
		return NormalizeEmulatorHost(fmt.Sprintf("http://%s:%s", external, port))
	}
	return NormalizeEmulatorHost(raw)
}
