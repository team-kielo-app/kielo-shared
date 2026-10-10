package media

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "nZtRohdNF9m3cKM24IcK4w"

func testSigner(t *testing.T) *CDNSigner {
	t.Helper()
	s, err := NewCDNSigner("media-signed-key", testKey)
	require.NoError(t, err)
	return s
}

// The reference values are computed independently (Python hmac/base64) from
// the documented Cloud CDN format.
func TestCDNSignerMatchesTheCloudCDNFormat(t *testing.T) {
	s := testSigner(t)
	expires := time.Unix(1760000400, 0)
	signed := s.SignURL("https://media.kielo.app/kielo-media-signed-test/support/u1/m1/main.webp", expires)
	assert.Equal(t, "https://media.kielo.app/kielo-media-signed-test/support/u1/m1/main.webp"+
		"?Expires=1760000400&KeyName=media-signed-key&Signature=wBlFiOLuWG5fZavrlRqIbtltvCg=", signed)

	query := s.SignURLPrefix("https://media.kielo.app/kielo-media-signed-test/support/u1/m1/", expires)
	assert.True(t, strings.HasSuffix(query, "&Signature=RjHYqvoqnL_YUyZ2RTojDWNRKBQ="), query)
}

func TestCDNSignerVerify(t *testing.T) {
	s := testSigner(t)
	now := time.Unix(1760000000, 0)
	signed := s.SignURL("https://media.kielo.app/b/support/x.webp", now.Add(time.Hour))
	require.NoError(t, s.Verify(signed, now))
	assert.ErrorIs(t, s.Verify(signed, now.Add(2*time.Hour)), ErrCDNSignature, "expired")
	assert.ErrorIs(t, s.Verify(strings.Replace(signed, "x.webp", "y.webp", 1), now), ErrCDNSignature, "another object")
	assert.ErrorIs(t, s.Verify("https://media.kielo.app/b/support/x.webp", now), ErrCDNSignature, "unsigned")
	other, err := NewCDNSigner("media-signed-key", "AAAAAAAAAAAAAAAAAAAAAA")
	require.NoError(t, err)
	assert.ErrorIs(t, other.Verify(signed, now), ErrCDNSignature, "wrong key")

	prefixed := "https://media.kielo.app/b/support/u1/hls/seg1.m4s?" +
		s.SignURLPrefix("https://media.kielo.app/b/support/u1/", now.Add(time.Hour))
	require.NoError(t, s.Verify(prefixed, now))
	assert.ErrorIs(t, s.Verify(strings.Replace(prefixed, "/u1/hls", "/u2/hls", 1), now), ErrCDNSignature,
		"a prefix signature covers only its prefix")
}

func TestDeliveryMintsByStorageClass(t *testing.T) {
	// The test runner points STORAGE_EMULATOR_HOST at fake-gcs; the storage
	// URL asserted below is the production form.
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	d := NewDelivery(DeliveryConfig{
		CDNBaseURL:    "https://media.kielo.app/{bucket}",
		PublicBucket:  "pub",
		SignedBucket:  "sig",
		PrivateBucket: "priv",
		Signer:        testSigner(t),
	})
	d.now = func() time.Time { return time.Date(2026, 10, 8, 12, 20, 0, 0, time.UTC) }

	assert.Equal(t, "https://media.kielo.app/pub/kielotv/e/m/preview.webp", d.ObjectURL("", "pub", "kielotv/e/m/preview.webp"))

	signed := d.ObjectURL("", "sig", "support/u/m/main.webp")
	require.True(t, strings.HasPrefix(signed, "https://media.kielo.app/sig/support/u/m/main.webp?Expires="), signed)
	require.NoError(t, d.Signer().Verify(signed, d.now()))
	assert.Contains(t, signed, "Expires=1791468000", "expires at a window boundary: 12:20 + 1h → 14:00")
	d.now = func() time.Time { return time.Date(2026, 10, 8, 12, 55, 0, 0, time.UTC) }
	assert.Equal(t, signed, d.ObjectURL("", "sig", "support/u/m/main.webp"), "identical within the window, so caches hit")

	assert.Empty(t, d.ObjectURL("", "priv", "conversations/u/m/t.json"), "a private object has no client URL")
	assert.Empty(t, d.ServeBaseURL("", "sig", "support/u/m"), "a signed URL cannot be extended with a path")
	assert.Equal(t, "https://media.kielo.app/pub/kielotv/e/m/", d.ServeBaseURL("", "pub", "kielotv/e/m"))

	legacy := d.ObjectURL("", "kielo-media-processor-${PROJECT_ID}", "x/main.webp")
	assert.True(t, strings.HasPrefix(legacy, "https://storage.googleapis.com/"), "an unknown bucket keeps its storage URL: %s", legacy)

	unsignable := NewDelivery(DeliveryConfig{CDNBaseURL: "https://media.kielo.app/{bucket}", SignedBucket: "sig"})
	assert.Empty(t, unsignable.ObjectURL("", "sig", "support/u/m/main.webp"), "never an unsigned URL for signed media")
}

func TestDeliveryEncodesTheSignedObjectPath(t *testing.T) {
	d := NewDelivery(DeliveryConfig{CDNBaseURL: "https://media.kielo.app/{bucket}", SignedBucket: "sig", Signer: testSigner(t)})
	u := d.ObjectURL("", "sig", "support/u/päivä kuva.webp")
	assert.Contains(t, u, "/support/u/p%C3%A4iv%C3%A4%20kuva.webp?", "the signed string is the one a client sends")
}

func TestDeliveryContextualizesTheDevCDNEmulator(t *testing.T) {
	d := NewDelivery(DeliveryConfig{
		CDNBaseURL:         "http://localhost:8097/{bucket}",
		CDNInternalBaseURL: "http://kielo-cdn-emulator:8080/{bucket}",
		PublicBucket:       "pub",
	})
	assert.Equal(t, "http://localhost:8097/pub/a.webp", d.ObjectURL("localhost", "pub", "a.webp"))
	assert.Equal(t, "http://192.168.1.20:8097/pub/a.webp", d.ObjectURL("192.168.1.20", "pub", "a.webp"), "a device on the LAN")
	assert.Equal(t, "http://kielo-cdn-emulator:8080/pub/a.webp", d.ObjectURL("kielo-cms", "pub", "a.webp"), "a container")

	// A URL minted for a container (user-service hydrating a support thread
	// through /internal/media/refs) reaches a device through the BFF.
	minted := d.ObjectURL("kielo-user-service", "pub", "a.webp?Signature=x")
	assert.Equal(t, "http://192.168.1.20:8097/pub/a.webp?Signature=x", d.ContextualizeURL("192.168.1.20:8084", minted))
	assert.Equal(t, "http://localhost:8097/pub/a.webp?Signature=x", d.ContextualizeURL("localhost", minted))
	assert.Equal(t, minted, d.ContextualizeURL("kielo-mobile-bff", minted))
	assert.Equal(t, "http://kielo-cdn-emulator:80801/a", d.ContextualizeURL("192.168.1.20", "http://kielo-cdn-emulator:80801/a"))

	prod := NewDelivery(DeliveryConfig{CDNBaseURL: "https://media.kielo.app/{bucket}", PublicBucket: "pub"})
	assert.Equal(t, "https://media.kielo.app/pub/a.webp", prod.ObjectURL("kielo-cms", "pub", "a.webp"))
}

// The access decisions of 2026-10-08: content and avatars are public, support
// screenshots are served signed, conversation artifacts are private. A change
// here moves assets between buckets (a migration), so it is pinned.
func TestProfileAccessClasses(t *testing.T) {
	want := map[string]AccessClass{
		"support-attachment": AccessSignedCDN,
		"convo-transcript":   AccessPrivate,
		"convo-review":       AccessPrivate,
		// Unreleased store listing material (#325).
		"store-listing-source": AccessPrivate,
		"store-listing-export": AccessPrivate,
	}
	for key, p := range profiles {
		expected, ok := want[key]
		if !ok {
			expected = AccessPublic
		}
		assert.Equal(t, expected, p.Access, key)
	}
}

func TestStorageBucketForFollowsTheProfileClass(t *testing.T) {
	d := NewDelivery(DeliveryConfig{PublicBucket: "pub", SignedBucket: "sig"})
	support, _ := ProfileFor("support-attachment")
	avatar, _ := ProfileFor("user-avatar")
	transcript, _ := ProfileFor("convo-transcript")
	assert.Equal(t, "sig", d.StorageBucketFor(support, true, "legacy"))
	assert.Equal(t, "pub", d.StorageBucketFor(avatar, true, "legacy"))
	assert.Equal(t, "legacy", d.StorageBucketFor(transcript, true, "legacy"), "no private target configured")
	assert.Equal(t, "legacy", d.StorageBucketFor(MediaProfile{}, false, "legacy"))
}
