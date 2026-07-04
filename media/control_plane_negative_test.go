package media

import (
	"testing"
	"time"
)

// These tests target the media control-plane's behavior on UNSUPPORTED and
// malformed inputs: unknown/empty profiles, disallowed MIME types, missing
// owners, malformed JSON, and the documented storage-path layout. The happy
// paths live in lifecycle_test.go; this file is the negative/edge complement.

// isZeroProfile reports whether p is the zero MediaProfile. MediaProfile
// contains slices so it cannot be compared with ==; checking the identifying
// scalar fields is sufficient to assert "no profile resolved".
func isZeroProfile(p MediaProfile) bool {
	return p.Key == "" && p.EntityType == "" && p.PathPrefix == "" &&
		len(p.AllowedMimes) == 0 && len(p.Variants) == 0 && p.Access == ""
}

func TestUploadRequestValidate_Table(t *testing.T) {
	cases := []struct {
		name    string
		req     UploadRequest
		wantErr bool
	}{
		{
			name: "valid request passes",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "image/png",
			},
		},
		{
			name: "valid request passes with empty filename and hash (not validated)",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "image/png",
				Filename: "",
				Hash:     "",
			},
		},
		{
			name: "unknown profile rejected",
			req: UploadRequest{
				Profile:  "does-not-exist",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "image/png",
			},
			wantErr: true,
		},
		{
			name: "empty profile rejected",
			req: UploadRequest{
				Profile:  "",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "image/png",
			},
			wantErr: true,
		},
		{
			name: "missing owner id rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user"},
				MimeType: "image/png",
			},
			wantErr: true,
		},
		{
			name: "missing owner type rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{ID: "u1"},
				MimeType: "image/png",
			},
			wantErr: true,
		},
		{
			name: "blank (whitespace) owner rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "  ", ID: "  "},
				MimeType: "image/png",
			},
			wantErr: true,
		},
		{
			name: "empty mime rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "",
			},
			wantErr: true,
		},
		{
			name: "blank (whitespace) mime rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "   ",
			},
			wantErr: true,
		},
		{
			name: "mime not in profile AllowedMimes rejected",
			req: UploadRequest{
				Profile:  "user-avatar",
				Owner:    OwnerRef{Type: "user", ID: "u1"},
				MimeType: "application/pdf",
			},
			wantErr: true,
		},
		{
			name: "unconstrained profile accepts any mime (empty AllowedMimes)",
			req: UploadRequest{
				Profile:  "article-content", // AllowedMimes empty => any allowed
				Owner:    OwnerRef{Type: "article", ID: "a1"},
				MimeType: "application/octet-stream",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.req.Validate()
			if c.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestProfileFor_UnknownAndEmpty(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"does-not-exist", "does-not-exist"},
		{"empty key", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := ProfileFor(c.key)
			if ok {
				t.Fatalf("ProfileFor(%q) ok = true, want false", c.key)
			}
			if !isZeroProfile(p) {
				t.Fatalf("ProfileFor(%q) returned non-zero profile %+v, want zero", c.key, p)
			}
		})
	}
}

func TestProfileForEntityType_Unknown(t *testing.T) {
	cases := []struct {
		name string
		typ  EntityType
	}{
		// EntityTypeGeneric is "" and no profile maps it (the registry guards
		// against p.EntityType == "" matches), so it must not resolve. Every
		// named legacy entity type now maps to a profile, so only the empty
		// and bogus cases remain unresolvable.
		{"generic/empty entity type", EntityTypeGeneric},
		{"bogus entity type", EntityType("TotallyNotAThing")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := ProfileForEntityType(c.typ)
			if ok {
				t.Fatalf("ProfileForEntityType(%q) ok = true, want false", c.typ)
			}
			if !isZeroProfile(p) {
				t.Fatalf("ProfileForEntityType(%q) returned non-zero profile %+v, want zero", c.typ, p)
			}
		})
	}
}

func TestComputeExpiresAt_ZeroAndTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("zero-TTL profile returns zero time", func(t *testing.T) {
		p, ok := ProfileFor("kielotv-video") // TTL == 0 (curated, kept indefinitely)
		if !ok {
			t.Fatalf("fixture profile missing")
		}
		if got := p.ComputeExpiresAt(now); !got.IsZero() {
			t.Fatalf("ComputeExpiresAt = %v, want zero time", got)
		}
	})

	t.Run("TTL profile returns createdAt+TTL", func(t *testing.T) {
		p, ok := ProfileFor("convo-transcript") // TTL == 365d
		if !ok {
			t.Fatalf("fixture profile missing")
		}
		want := now.Add(p.Retention.TTL)
		if got := p.ComputeExpiresAt(now); !got.Equal(want) {
			t.Fatalf("ComputeExpiresAt = %v, want %v", got, want)
		}
	})

	t.Run("explicit negative TTL treated as indefinite", func(t *testing.T) {
		p := MediaProfile{Retention: RetentionPolicy{TTL: -time.Hour}}
		if got := p.ComputeExpiresAt(now); !got.IsZero() {
			t.Fatalf("ComputeExpiresAt with negative TTL = %v, want zero time", got)
		}
	})
}

func TestAssetMetadataFromJSON_EmptyAndMalformed(t *testing.T) {
	t.Run("nil input returns zero value, no error", func(t *testing.T) {
		m, err := AssetMetadataFromJSON(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m != (AssetMetadata{}) {
			t.Fatalf("got %+v, want zero AssetMetadata", m)
		}
	})

	t.Run("empty input returns zero value, no error", func(t *testing.T) {
		m, err := AssetMetadataFromJSON([]byte{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m != (AssetMetadata{}) {
			t.Fatalf("got %+v, want zero AssetMetadata", m)
		}
	})

	t.Run("malformed JSON returns error and zero value, no panic", func(t *testing.T) {
		for _, raw := range [][]byte{
			[]byte("{not json"),
			[]byte("["),
			[]byte(`{"original_width": "not-a-number"}`),
		} {
			m, err := AssetMetadataFromJSON(raw)
			if err == nil {
				t.Fatalf("AssetMetadataFromJSON(%q) err = nil, want error", raw)
			}
			if m != (AssetMetadata{}) {
				t.Fatalf("AssetMetadataFromJSON(%q) m = %+v, want zero on error", raw, m)
			}
		}
	})
}

func TestBuildMediaRef_EmptyAndMalformedInputs(t *testing.T) {
	meta := AssetMetadata{
		Thumbhash:      "abc",
		LqipDataURI:    "data:image/png;base64,xx",
		OriginalWidth:  640,
		OriginalHeight: 480,
	}

	t.Run("nil variants keeps placeholder, empty URL and variants", func(t *testing.T) {
		ref := BuildMediaRef("https://cdn.example/base", nil, meta, "main")
		if ref.URL != "" {
			t.Fatalf("URL = %q, want empty when no variants", ref.URL)
		}
		if ref.Variants != nil {
			t.Fatalf("Variants = %v, want nil when no variants", ref.Variants)
		}
		if ref.Thumbhash != meta.Thumbhash || ref.LqipURI != meta.LqipDataURI {
			t.Fatalf("placeholder not carried through: %+v", ref)
		}
		if ref.Width != meta.OriginalWidth || ref.Height != meta.OriginalHeight {
			t.Fatalf("dimensions not carried through: %+v", ref)
		}
	})

	t.Run("empty serve base keeps placeholder, empty URL and variants", func(t *testing.T) {
		variants := map[string]Variant{"main": {Path: "x/main.webp", Width: 100, Height: 50}}
		ref := BuildMediaRef("", variants, meta, "main")
		if ref.URL != "" {
			t.Fatalf("URL = %q, want empty when serve base empty", ref.URL)
		}
		if ref.Variants != nil {
			t.Fatalf("Variants = %v, want nil when serve base empty", ref.Variants)
		}
		if ref.Thumbhash != meta.Thumbhash {
			t.Fatalf("placeholder not carried through: %+v", ref)
		}
	})

	t.Run("empty everything does not panic and returns zero-ish ref", func(t *testing.T) {
		ref := BuildMediaRef("", nil, AssetMetadata{})
		if ref.URL != "" || ref.Variants != nil || ref.Thumbhash != "" {
			t.Fatalf("expected zero-ish MediaRef, got %+v", ref)
		}
	})

	t.Run("variants with empty paths are skipped, no panic", func(t *testing.T) {
		variants := map[string]Variant{
			"main":  {Path: ""},
			"thumb": {Path: ""},
		}
		ref := BuildMediaRef("https://cdn.example/base", variants, AssetMetadata{}, "main", "thumb")
		if ref.URL != "" {
			t.Fatalf("URL = %q, want empty when all variant paths empty", ref.URL)
		}
		if len(ref.Variants) != 0 {
			t.Fatalf("Variants = %v, want empty when all variant paths empty", ref.Variants)
		}
	})

	t.Run("no matching primary key leaves URL empty but maps non-empty variants", func(t *testing.T) {
		variants := map[string]Variant{"preview": {Path: "x/preview.webp"}}
		ref := BuildMediaRef("https://cdn.example/base", variants, AssetMetadata{}, "main")
		if ref.URL != "" {
			t.Fatalf("URL = %q, want empty when no primary key matches", ref.URL)
		}
		if ref.Variants["preview"] == "" {
			t.Fatalf("expected non-primary variant URL to still be mapped, got %v", ref.Variants)
		}
	})
}

func TestResolveStoragePath_OwnerLayout(t *testing.T) {
	avatar, _ := ProfileFor("user-avatar")           // profile keys the path on owner id
	article, _ := ProfileFor("article-thumbnail")    // profile keys the path on entity id
	noIDProfile := MediaProfile{PathPrefix: "loose"} // neither owner nor entity id

	cases := []struct {
		name             string
		profile          MediaProfile
		ownerID, mediaID string
		want             string
	}{
		// Documented layout: <PathPrefix>[/<ownerID>]/<mediaID>
		{"owner-id profile with owner", avatar, "u1", "m1", "user-assets/u1/m1"},
		{"owner-id profile without owner omits segment", avatar, "", "m1", "user-assets/m1"},
		{"entity-id profile with owner", article, "a1", "m2", "articles/a1/m2"},
		{"entity-id profile without owner omits segment", article, "", "m2", "articles/m2"},
		{"profile not including ids never adds owner segment", noIDProfile, "u9", "m9", "loose/m9"},
		{"empty mediaID dropped", avatar, "u1", "", "user-assets/u1"},
		{"empty owner and media yields prefix only", avatar, "", "", "user-assets"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveStoragePath(c.profile, c.ownerID, c.mediaID); got != c.want {
				t.Fatalf("ResolveStoragePath = %q, want %q", got, c.want)
			}
		})
	}
}
