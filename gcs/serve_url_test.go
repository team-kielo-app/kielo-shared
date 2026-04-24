package gcs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for GCS serve-URL construction. Every service that references
// a stored object goes through these helpers — mobile-bff when proxying
// media, ingest-processor when writing processed audio, content-service
// when generating signed-URL redirects. A silent regression here means
// broken image / audio URLs across the entire platform.
//
// Contracts pinned here:
//   - BuildServeBaseURL: CDN > emulator > public-GCS, trailing slash
//     on prefix, missing bucket → "".
//   - BuildObjectURL: URL-encodes the object path so special chars
//     don't break the GCS JSON API path segment.
//   - BuildStoragePrefix: does NOT URL-encode — it's a prefix, not a
//     specific object; trailing slash normalization.
//   - IsStorageAPIPath: matches the two GCS API prefixes exactly.
//   - buildStoragePath: strips /storage or /storage/v1 suffix to avoid
//     doubled path segments when callers pass an already-qualified base.

func TestBuildServeBaseURL_EmptyBucketReturnsEmpty(t *testing.T) {
	// Callers pass the empty string when config is missing. The
	// helper must return "" cleanly rather than e.g.
	// "https://storage.googleapis.com//" — otherwise downstream
	// URL joining silently produces broken URLs.
	assert.Equal(t, "", BuildServeBaseURL("", "media", ""))
}

func TestBuildServeBaseURL_CDNOverridesEverything(t *testing.T) {
	// CDN base wins even when an emulator is configured. This is
	// the production path where we want to hide storage.googleapis
	// behind a Cloudflare/etc CDN.
	t.Setenv("STORAGE_EMULATOR_HOST", "http://localhost:4443")
	got := BuildServeBaseURL("bucket", "media", "https://cdn.kielo.app")
	assert.Equal(t, "https://cdn.kielo.app/media/", got)
}

func TestBuildServeBaseURL_CDNTrailingSlashIsTrimmed(t *testing.T) {
	// CDN URL may or may not carry a trailing slash; both must produce
	// the same output so URL-join doesn't end up with "//" in the middle.
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	got := BuildServeBaseURL("bucket", "media", "https://cdn.kielo.app/")
	assert.Equal(t, "https://cdn.kielo.app/media/", got)
}

func TestBuildServeBaseURL_CDNEmptyPrefix(t *testing.T) {
	// No prefix → no trailing segment, but the CDN base still ends
	// with "/" so object paths can be appended directly.
	got := BuildServeBaseURL("bucket", "", "https://cdn.kielo.app")
	assert.Equal(t, "https://cdn.kielo.app/", got)
}

func TestBuildServeBaseURL_PublicGCSFallback(t *testing.T) {
	// No CDN, no emulator → the canonical public GCS URL. Useful
	// for dev without the emulator configured.
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	got := BuildServeBaseURL("bucket", "media", "")
	assert.Equal(t, "https://storage.googleapis.com/bucket/media/", got)
}

func TestBuildServeBaseURL_TrimsSurroundingSlashesOnPrefix(t *testing.T) {
	// The prefix may arrive with leading/trailing slashes depending on
	// the caller. Normalize to a single trailing slash so we never
	// produce "bucket//media//".
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	got := BuildServeBaseURL("bucket", "/media/", "")
	assert.Equal(t, "https://storage.googleapis.com/bucket/media/", got)
}

func TestBuildObjectURL_UsesStorageAPIPath(t *testing.T) {
	// The GCS JSON API requires /storage/v1/b/<bucket>/o/<obj> with
	// the object segment URL-encoded. Exact format pinned.
	got := BuildObjectURL("http://emu:4443", "my-bucket", "path/to/file.mp3")
	assert.Equal(t, "http://emu:4443/storage/v1/b/my-bucket/o/path%2Fto%2Ffile.mp3", got)
}

func TestBuildObjectURL_EncodesSpecialChars(t *testing.T) {
	// Spaces, plus signs, and other URL-reserved chars in the object
	// name must be percent-encoded — otherwise the API returns 404.
	got := BuildObjectURL("http://emu", "b", "folder/file name.mp3")
	assert.Contains(t, got, "folder%2Ffile%20name.mp3")
}

func TestBuildObjectURL_StripsDoubleSlashFromBase(t *testing.T) {
	// If caller passes "http://emu/" (trailing slash) the output must
	// still land at a single slash between host and /storage/v1/.
	got := BuildObjectURL("http://emu/", "b", "obj")
	assert.Equal(t, "http://emu/storage/v1/b/b/o/obj", got)
}

func TestBuildObjectURL_StripsAlreadyQualifiedStorageSuffix(t *testing.T) {
	// Some callers pass "http://emu/storage/v1" or "http://emu/storage"
	// as the base. Both must be normalized so we don't build
	// "…/storage/v1/storage/v1/b/…" (doubled segment).
	got1 := BuildObjectURL("http://emu/storage/v1", "b", "obj")
	got2 := BuildObjectURL("http://emu/storage", "b", "obj")
	assert.Equal(t, "http://emu/storage/v1/b/b/o/obj", got1)
	assert.Equal(t, "http://emu/storage/v1/b/b/o/obj", got2)
}

func TestBuildStoragePrefix_DoesNotEncodePrefix(t *testing.T) {
	// Unlike BuildObjectURL, BuildStoragePrefix must NOT encode the
	// prefix — it's used for listing, which treats "/" as a delimiter.
	// Encoding would defeat the prefix semantics.
	got := BuildStoragePrefix("http://emu", "b", "media/thumbnails")
	assert.Equal(t, "http://emu/storage/v1/b/b/o/media/thumbnails/", got)
}

func TestBuildStoragePrefix_EmptyPrefixOmitsTrailing(t *testing.T) {
	// An empty prefix leaves no trailing slash on the listing path
	// — the base is already slash-terminated.
	got := BuildStoragePrefix("http://emu", "b", "")
	assert.Equal(t, "http://emu/storage/v1/b/b/o/", got)
}

func TestBuildObjectFetchURL_AppendsAltMedia(t *testing.T) {
	// The ?alt=media suffix is what turns a metadata read into a
	// content fetch. Without it, the API returns JSON metadata, not
	// the object bytes — causing every media download to corrupt.
	got := BuildObjectFetchURL("http://emu", "b", "obj")
	assert.Equal(t, "http://emu/storage/v1/b/b/o/obj?alt=media", got)
}

func TestIsStorageAPIPath_RecognizesBothAPIPrefixes(t *testing.T) {
	// Used by reverse proxies to distinguish GCS API calls from
	// direct object URLs. Must match both the read and the upload
	// API prefixes (e.g. mobile-bff rewrites both).
	assert.True(t, IsStorageAPIPath("/storage/v1/b/my-bucket/o/foo"))
	assert.True(t, IsStorageAPIPath("/upload/storage/v1/b/my-bucket/o"))
}

func TestIsStorageAPIPath_RejectsUnrelatedPaths(t *testing.T) {
	// CDN or public-GCS URLs (e.g. "/my-bucket/foo.mp3") are NOT
	// storage API paths and must not be rewritten.
	assert.False(t, IsStorageAPIPath("/my-bucket/foo.mp3"))
	assert.False(t, IsStorageAPIPath("/api/v1/content"))
	assert.False(t, IsStorageAPIPath(""))
	assert.False(t, IsStorageAPIPath("/storage/v2/b/foo"), "v2 must not match v1")
}
