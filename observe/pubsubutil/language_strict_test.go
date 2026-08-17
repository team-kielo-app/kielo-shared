package pubsubutil

import (
	"context"
	"errors"
	"testing"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// WithLanguageFromAttributesStrict must never return (ctx, nil) with no
// language attached. A consumer trusting that pair scopes its per-language
// writes to nothing: the unqualified table name resolves to nothing (the
// global tables are gone since V235), the DB error reads as transient, and
// the message NACKs forever. Both a missing and an unusable attribute are
// permanent conditions and must surface as errors.
func TestWithLanguageFromAttributesStrict_AttachesOnlyValidLanguages(t *testing.T) {
	cases := []struct {
		name    string
		attrs   map[string]string
		wantErr error
		wantCtx string // language expected on ctx; "" when an error is expected
	}{
		{"missing attribute", map[string]string{"event_type": "x"}, ErrLanguageRequired, ""},
		{"nil attributes", nil, ErrLanguageRequired, ""},
		{"empty value", map[string]string{LanguageAttribute: ""}, ErrLanguageRequired, ""},
		{"support-only locale", map[string]string{LanguageAttribute: "vi"}, ErrLanguageInvalid, ""},
		{"unknown code", map[string]string{LanguageAttribute: "garbage"}, ErrLanguageInvalid, ""},
		{"injection attempt", map[string]string{LanguageAttribute: "public; DROP"}, ErrLanguageInvalid, ""},
		{"canonical fi", map[string]string{LanguageAttribute: "fi"}, nil, "fi"},
		{"canonical sv", map[string]string{LanguageAttribute: "sv"}, nil, "sv"},
		{"uppercase normalizes", map[string]string{LanguageAttribute: "FI"}, nil, "fi"},
		{"region tag collapses", map[string]string{LanguageAttribute: "fi-FI"}, nil, "fi"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := WithLanguageFromAttributesStrict(context.Background(), tc.attrs)
			lang, attached := sharedDB.LanguageFromContext(ctx)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if attached {
					t.Fatalf("language %q attached despite error", lang)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// The load-bearing invariant: err == nil implies an attached,
			// usable language — never a silently language-less ctx.
			if !attached {
				t.Fatal("returned (ctx, nil) with no language attached")
			}
			if lang != tc.wantCtx {
				t.Fatalf("ctx language = %q, want %q", lang, tc.wantCtx)
			}
		})
	}
}

// Pins the cross-package agreement the helper's guarantee used to rest on
// implicitly: everything locale/ accepts as a learning language must also be
// attachable by db/. If a third language is ever added to one set first,
// this fails here rather than as a redelivery loop in a consumer.
func TestLearningLanguageSetsAgreeAcrossPackages(t *testing.T) {
	for _, lang := range []string{"fi", "sv"} {
		if err := sharedDB.ValidateLearningLanguageIdent(lang); err != nil {
			t.Fatalf("locale accepts %q but db rejects it: %v", lang, err)
		}
	}
	for _, candidate := range []string{"fi", "sv", "vi", "en", "ja", "ru", "sl"} {
		ctx, err := WithLanguageFromAttributesStrict(
			context.Background(), map[string]string{LanguageAttribute: candidate},
		)
		_, attached := sharedDB.LanguageFromContext(ctx)
		if err == nil && !attached {
			t.Fatalf("%q passed the helper but did not attach — set drift", candidate)
		}
	}
}
