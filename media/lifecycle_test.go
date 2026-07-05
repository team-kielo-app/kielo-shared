package media

import (
	"testing"
	"time"
)

func TestResolveStoragePath(t *testing.T) {
	avatar, _ := ProfileFor("user-avatar")        // IncludeOwnerID
	article, _ := ProfileFor("article-thumbnail") // IncludeEntityID
	cases := []struct {
		name, owner, media string
		profile            MediaProfile
		want               string
	}{
		{"avatar with owner", "u1", "m1", avatar, "user-assets/u1/m1"},
		{"article with entity", "a1", "m2", article, "articles/a1/m2"},
		{"no owner segment when blank", "", "m3", avatar, "user-assets/m3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveStoragePath(c.profile, c.owner, c.media); got != c.want {
				t.Fatalf("ResolveStoragePath = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUploadRequestValidate(t *testing.T) {
	ok := UploadRequest{
		Profile:  "user-avatar",
		Owner:    OwnerRef{Type: "user", ID: "u1"},
		MimeType: "image/png",
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid request errored: %v", err)
	}

	bad := []UploadRequest{
		{Profile: "nope", Owner: OwnerRef{Type: "user", ID: "u1"}, MimeType: "image/png"},
		{Profile: "user-avatar", Owner: OwnerRef{Type: "user"}, MimeType: "image/png"},
		{Profile: "user-avatar", Owner: OwnerRef{Type: "user", ID: "u1"}},
		{Profile: "user-avatar", Owner: OwnerRef{Type: "user", ID: "u1"}, MimeType: "application/pdf"},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Fatalf("bad request %d passed validation", i)
		}
	}
}

func TestComputeExpiresAt(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	indefinite, _ := ProfileFor("kielotv-video") // TTL 0 — curated, kept until owner-delete
	if got := indefinite.ComputeExpiresAt(now); !got.IsZero() {
		t.Fatalf("indefinite profile should not expire, got %v", got)
	}

	ttl, _ := ProfileFor("convo-transcript") // TTL 365d
	got := ttl.ComputeExpiresAt(now)
	if got.IsZero() {
		t.Fatalf("TTL profile should have an expiry")
	}
	if !got.After(now) {
		t.Fatalf("expiry %v should be after %v", got, now)
	}

	// Articles are ephemeral (re-scraped daily): 30d TTL, reconciler-reaped.
	article, _ := ProfileFor("article-thumbnail")
	exp := article.ComputeExpiresAt(now)
	if exp.IsZero() || !exp.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("article-thumbnail should expire at now+30d, got %v", exp)
	}
}
