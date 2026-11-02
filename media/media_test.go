package media

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for the media-host context and entity-type helpers. These are
// used across every service that serves or references user-uploaded
// media — mobile-bff tags outgoing signed URLs with the client's
// external host, and each downstream handler reads it via
// RequestHostFromContext. A silent regression here would cause every
// media URL in the mobile app to point at the internal Docker hostname
// and fail to load.

func TestIsValidEntityType_AcceptsAllKnownTypes(t *testing.T) {
	// Every entry in ValidEntityTypes must be accepted — this catches
	// a slice-vs-constant mismatch if someone adds a new EntityType
	// constant but forgets to append it to ValidEntityTypes.
	for _, entity := range ValidEntityTypes {
		assert.True(t, IsValidEntityType(string(entity)),
			"IsValidEntityType should accept %q from the exported allowlist", entity)
	}
}

func TestIsValidEntityType_RejectsUnknown(t *testing.T) {
	assert.False(t, IsValidEntityType("RandomThing"))
	assert.False(t, IsValidEntityType("userAvatar"))   // case-sensitive
	assert.False(t, IsValidEntityType(" UserAvatar ")) // no trim
}

func TestIsValidEntityType_RejectsGenericEmpty(t *testing.T) {
	// EntityTypeGeneric ("") is defined but intentionally NOT in
	// ValidEntityTypes — unknown uploads must be rejected, not
	// accepted by default. Pin this so a future "helpful" refactor
	// that appends EntityTypeGeneric to the allowlist is caught.
	assert.False(t, IsValidEntityType(""),
		"empty string must not be treated as a valid entity type")
}

func TestWithRequestHost_StoresTrimmedNonEmptyValue(t *testing.T) {
	ctx := WithRequestHost(context.Background(), "  api.example.com  ")
	got := RequestHostFromContext(ctx)
	assert.Equal(t, "api.example.com", got)
}

func TestWithRequestHost_SkipsBlankValues(t *testing.T) {
	// Blank / whitespace-only input is a no-op: the original context
	// is returned unchanged so a later layer can still attach a real
	// value. Observed via RequestHostFromContext returning "" — no
	// value has been attached at this key.
	base := context.Background()
	assert.Equal(t, "", RequestHostFromContext(WithRequestHost(base, "")))
	assert.Equal(t, "", RequestHostFromContext(WithRequestHost(base, "  \t\n")))
}

func TestRequestHostFromContext_HandlesNilAndMissing(t *testing.T) {
	// Defensive: some plumbing paths may inadvertently pass a nil
	// context. The helper must not panic — return "" cleanly.
	//lint:ignore SA1012 deliberately testing nil-safety of the helper
	//nolint:staticcheck // SA1012: deliberately testing nil-safety
	assert.Equal(t, "", RequestHostFromContext(nil))

	// Context present but no host attached — return "" cleanly.
	assert.Equal(t, "", RequestHostFromContext(context.Background()))
}

func TestEffectiveClientHost_PrefersXForwardedHost(t *testing.T) {
	// In a proxied setup (mobile-bff → downstream), Host is the
	// internal docker name. X-Forwarded-Host carries the original
	// external host — which is the one that must appear in
	// media URLs returned to the mobile app.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "mobile-bff.internal:8085"
	req.Header.Set("X-Forwarded-Host", "api.kielo.app")
	assert.Equal(t, "api.kielo.app", EffectiveClientHost(req))
}

func TestEffectiveClientHost_ParsesXForwardedChain(t *testing.T) {
	// X-Forwarded-Host may be a comma-separated chain when multiple
	// proxies are in front. The origin (first entry) wins.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Host", "api.kielo.app, gateway.local, mobile-bff.local")
	assert.Equal(t, "api.kielo.app", EffectiveClientHost(req))
}

func TestEffectiveClientHost_TrimsXForwardedHeaderWhitespace(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "internal"
	req.Header.Set("X-Forwarded-Host", "  api.kielo.app  ")
	assert.Equal(t, "api.kielo.app", EffectiveClientHost(req))
}

func TestEffectiveClientHost_FallsBackToRequestHost(t *testing.T) {
	// No X-Forwarded-Host header → Host wins. This is the
	// non-proxied direct-call path.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "direct.example.com"
	assert.Equal(t, "direct.example.com", EffectiveClientHost(req))
}

func TestEffectiveClientHost_HandlesNilRequest(t *testing.T) {
	// Defensive: callers sometimes pass req from contexts where
	// request may be nil (background jobs, reused handler plumbing).
	assert.Equal(t, "", EffectiveClientHost(nil))
}

func TestEffectiveClientHost_SkipsBlankXForwardedHeader(t *testing.T) {
	// A header present but blank should NOT be preferred — that
	// would return "" and misclassify the request as un-hosted.
	// Instead, fall through to Host.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "direct.example.com"
	req.Header.Set("X-Forwarded-Host", "   ")
	assert.Equal(t, "direct.example.com", EffectiveClientHost(req))
}

// Social post videos are fetched by Buffer from a public URL: a public
// progressive mp4 "main" rendition plus a poster frame, never reaped.
func TestSocialPostVideoProfile(t *testing.T) {
	p, ok := ProfileFor("social-post-video")
	if !ok {
		t.Fatal("social-post-video profile missing")
	}
	if p.Access != AccessPublic {
		t.Fatalf("access = %v, want public (Buffer fetches the file anonymously)", p.Access)
	}
	if p.Retention != (RetentionPolicy{}) {
		t.Fatalf("retention = %+v, want keep forever", p.Retention)
	}
	var main, preview bool
	for _, v := range p.Variants {
		main = main || (v.Name == "main" && v.Format == "mp4" && v.MaxShortSide == 1080)
		preview = preview || (v.Name == "preview" && v.Format == "webp")
	}
	if !main || !preview {
		t.Fatalf("variants = %+v, want main mp4 (1080 short side) and webp preview", p.Variants)
	}
	if got, ok := ProfileForRelatedEntity("SocialPost"); !ok || got.Key != "social-post-video" {
		t.Fatalf("SocialPost alias = %q %v", got.Key, ok)
	}
}

// Carousel slides and their sound are public and kept as uploaded: Buffer and
// the KTV toolbox fetch them anonymously, and Instagram takes JPEG only.
func TestSocialPostCarouselProfiles(t *testing.T) {
	img, ok := ProfileFor("social-post-image")
	if !ok || !img.PassThrough || img.Access != AccessPublic || img.Retention != (RetentionPolicy{}) {
		t.Fatalf("social-post-image = %+v %v", img, ok)
	}
	if len(img.AllowedMimes) != 1 || img.AllowedMimes[0] != "image/jpeg" {
		t.Fatalf("image mimes = %v, want JPEG only", img.AllowedMimes)
	}
	aud, ok := ProfileFor("social-post-audio")
	if !ok || !aud.PassThrough || aud.Access != AccessPublic {
		t.Fatalf("social-post-audio = %+v %v", aud, ok)
	}
}
