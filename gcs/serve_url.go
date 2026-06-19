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
		// CDN_SERVING_BASE_URL may carry a "{bucket}" placeholder (e.g.
		// "https://media.kielo.app/{bucket}") so one CDN host can front
		// multiple buckets — inject the real bucket here. No-op when the
		// base has no placeholder. Without this the literal "{bucket}"
		// leaks into served URLs (e.g. kielotv thumbnails).
		base = strings.ReplaceAll(base, "{bucket}", bucket)
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

// JoinServeBaseAndObjectPath combines a serve-base URL (as returned by
// BuildServeBaseURL) with a relative object path. It correctly handles
// two cases:
//
//   - **Direct or CDN URL** (path ends in "/"): appends the object
//     path with leading-slash normalization. Example:
//     "https://cdn.example.com/assets/" + "img.jpg" →
//     "https://cdn.example.com/assets/img.jpg".
//
//   - **GCS storage API URL** (".../storage/v1/b/<bucket>/o/<prefix>/"):
//     re-encodes the full object path with the proper "/o/" segment
//     and appends "?alt=media" so the returned URL is fetchable.
//     Required for the gcs-emulator so fake-gcs-server returns the
//     bytes rather than the JSON object-metadata document.
//
// Behavior corners (pinned by tests in serve_url_test.go and the
// historical url_test.go under kielo-shared/media):
//
//   - Empty / whitespace base returns "".
//   - Empty / whitespace variantPath returns the base unchanged.
//   - Base that has a query string returns base unchanged (refusal —
//     callers shouldn't be passing pre-queried bases here, and silently
//     concatenating would produce malformed URLs).
//   - Base that doesn't end in "/" AND isn't a storage-API path returns
//     base unchanged ("fail obviously" — caller should pass a slash-
//     terminated base, and we don't silently guess).
//
// This used to live as an unexported `joinServeBaseAndVariantPath`
// in `kielo-shared/media/url.go`, called only from PreferredVariantURL.
// It was promoted here in 2026-05-21 so non-media callers (ambient
// audio resolver, localization bundle URL builder) can reuse the same
// shape-aware join instead of hand-rolling `fmt.Sprintf("https://...")`
// which silently skipped CDN propagation, emulator rewriting, and
// path escaping.
func JoinServeBaseAndObjectPath(serveBaseURL, objectPath string) string {
	base := strings.TrimSpace(serveBaseURL)
	if base == "" {
		return ""
	}
	oPath := strings.TrimSpace(objectPath)
	if oPath == "" {
		return base
	}

	if parsedBase, err := url.Parse(base); err == nil && parsedBase != nil {
		if strings.TrimSpace(parsedBase.RawQuery) != "" || !strings.HasSuffix(parsedBase.Path, "/") {
			return base
		}
		if IsStorageAPIPath(parsedBase.Path) {
			bucketAndPrefix, _ := strings.CutPrefix(parsedBase.Path, StorageAPIPath)
			if bucketPart, prefixPart, ok := strings.Cut(bucketAndPrefix, "/o/"); ok {
				bucket := strings.TrimSpace(bucketPart)
				objectPrefix := strings.Trim(prefixPart, "/")
				combined := strings.TrimLeft(oPath, "/")
				if objectPrefix != "" {
					combined = objectPrefix + "/" + combined
				}
				if bucket != "" && combined != "" {
					hostBase := fmt.Sprintf("%s://%s", parsedBase.Scheme, parsedBase.Host)
					return BuildObjectFetchURL(hostBase, bucket, combined)
				}
			}
		}
	}

	if strings.HasSuffix(base, "/") {
		return base + strings.TrimLeft(oPath, "/")
	}
	return base + "/" + strings.TrimLeft(oPath, "/")
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
