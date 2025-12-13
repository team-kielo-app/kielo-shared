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
	if portStr := os.Getenv("PORT_GCS_EMULATOR"); portStr != "" {
		host := os.Getenv("HOST_IP")
		if host == "" {
			host = "localhost"
			if isRunningInDocker() {
				host = "gcs-emulator"
			}
		}
		base := fmt.Sprintf("http://%s:%s", host, portStr)
		return NormalizeEmulatorHost(base)
	}

	emulatorHost := os.Getenv("STORAGE_EMULATOR_HOST")
	if external := os.Getenv("HOST_IP"); external != "" {
		emulatorHost = fmt.Sprintf("http://%s:4443/storage/v1/", external)
	}
	return NormalizeEmulatorHost(emulatorHost)
}
