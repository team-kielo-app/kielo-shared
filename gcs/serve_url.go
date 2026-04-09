package gcs

import (
	"fmt"
	"net/url"
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
		return BuildStoragePrefix(base, bucket, prefix)
	}

	// Default GCS public URL.
	return fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucket, prefix)
}

// StorageAPIPath is the GCS JSON API path prefix for object operations.
const StorageAPIPath = "/storage/v1/b/"

// UploadAPIPath is the GCS JSON API path prefix for resumable uploads.
const UploadAPIPath = "/upload/storage/v1/b/"

// BuildObjectURL builds a GCS object URL: {base}/storage/v1/b/{bucket}/o/{encodedObject}
// The base should be scheme://host[:port], optionally with /storage/v1 suffix (stripped).
// The object path is URL-encoded for safe use in the GCS API path.
func BuildObjectURL(base, bucket, objectPath string) string {
	return buildStoragePath(base, bucket) + url.PathEscape(objectPath)
}

// BuildStoragePrefix builds a GCS prefix URL: {base}/storage/v1/b/{bucket}/o/{prefix}/
// Unlike BuildObjectURL, the prefix is NOT URL-encoded (it's a path prefix, not a specific object).
func BuildStoragePrefix(base, bucket, prefix string) string {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return buildStoragePath(base, bucket) + prefix
}

func buildStoragePath(base, bucket string) string {
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/storage/v1")
	base = strings.TrimSuffix(base, "/storage")
	return fmt.Sprintf("%s%s%s/o/", base, StorageAPIPath, bucket)
}

// BuildObjectFetchURL builds a GCS object URL with ?alt=media for fetching content.
func BuildObjectFetchURL(base, bucket, objectPath string) string {
	return BuildObjectURL(base, bucket, objectPath) + "?alt=media"
}

// IsStorageAPIPath returns true if the URL path is a GCS storage API path.
func IsStorageAPIPath(urlPath string) bool {
	return strings.HasPrefix(urlPath, StorageAPIPath) || strings.HasPrefix(urlPath, UploadAPIPath)
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
