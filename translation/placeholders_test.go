package translation

import (
	"strings"
	"testing"
)

func TestMaskingLeavesOrdinaryProseAlone(t *testing.T) {
	for _, text := range []string{
		"In the news today.",
		"Outside your usual topics.",
		// The reason the printf pattern is a tight verb set and not the full
		// printf grammar: a permissive one matches the "% o" here.
		"50% off this week",
		"Progress: 80% complete",
		"100%",
	} {
		masked, tokens := maskPlaceholders(text)
		if masked != text || tokens != nil {
			t.Errorf("prose was masked: %q -> %q tokens=%v", text, masked, tokens)
		}
		if HasPlaceholders(text) {
			t.Errorf("HasPlaceholders true for prose: %q", text)
		}
	}
}

func TestRoundTripPreservesTemplateAndPrintf(t *testing.T) {
	for _, text := range []string{
		"{{.data.due_count}} {{.data.learning_language_name}} words to review",
		`{{if and (eq .data.copy_variant "named") .data.sample_term}}Still remember “{{.data.sample_term}}”?{{else}}{{.data.due_count}} words{{end}}`,
		"Uses %d words you're learning.",
		"You learned “%s” this week. It appears here.",
		"%d of %d done (%s)",
		"Save 50%% today",
	} {
		masked, tokens := maskPlaceholders(text)
		if strings.Contains(masked, "{{") {
			t.Errorf("template action survived masking: %q", masked)
		}
		restored, err := restorePlaceholders(masked, tokens)
		if err != nil {
			t.Fatalf("round trip failed for %q: %v", text, err)
		}
		if restored != text {
			t.Errorf("round trip changed text\n got: %q\nwant: %q", restored, text)
		}
	}
}

// Word order differs by language, and a Go template renders the same whichever
// order its actions appear in. Reordering must be accepted.
func TestReorderedPlaceholdersAreAccepted(t *testing.T) {
	_, tokens := maskPlaceholders("{{.a}} then {{.b}}")
	restored, err := restorePlaceholders("[[1]] sitten [[0]]", tokens)
	if err != nil {
		t.Fatalf("reordering rejected: %v", err)
	}
	if restored != "{{.b}} sitten {{.a}}" {
		t.Errorf("got %q", restored)
	}
}

// Translators add spacing around punctuation; that must not break restore.
func TestWhitespaceInsideTokensIsTolerated(t *testing.T) {
	_, tokens := maskPlaceholders("Uses %d words")
	restored, err := restorePlaceholders("Utilize [ [ 0 ] ] mots", tokens)
	if err != nil {
		t.Fatalf("spaced token rejected: %v", err)
	}
	if restored != "Utilize %d mots" {
		t.Errorf("got %q", restored)
	}
}

// The whole point: a translator that eats a placeholder must not produce a
// usable string, because the caller would persist it as approved.
func TestDroppedPlaceholderIsRejected(t *testing.T) {
	_, tokens := maskPlaceholders("Uses %d words you're learning.")
	if _, err := restorePlaceholders("Kullandığın kelimeler.", tokens); err == nil {
		t.Fatal("a dropped verb was accepted; Sprintf would render a MISSING marker into a live push")
	}
}

func TestDuplicatedPlaceholderIsRejected(t *testing.T) {
	_, tokens := maskPlaceholders("Uses %d words")
	if _, err := restorePlaceholders("[[0]] ja [[0]] sanaa", tokens); err == nil {
		t.Fatal("a duplicated placeholder was accepted")
	}
}

func TestInventedPlaceholderIsRejected(t *testing.T) {
	_, tokens := maskPlaceholders("Uses %d words")
	if _, err := restorePlaceholders("[[0]] ja [[7]] sanaa", tokens); err == nil {
		t.Fatal("an index that was never issued was accepted")
	}
}

// A model that translates the identifier inside an action — the real
// autotranslate bug, {{.data.due_count}} -> {{.data.số_từ}} — leaves the
// masked form without the token, so restore rejects it.
func TestTranslatedIdentifierIsRejected(t *testing.T) {
	_, tokens := maskPlaceholders("{{.data.due_count}} words to review")
	if _, err := restorePlaceholders("{{.data.số_từ}} từ cần ôn", tokens); err == nil {
		t.Fatal("a translated identifier was accepted")
	}
}

func TestRestoreIsANoOpWithoutTokens(t *testing.T) {
	restored, err := restorePlaceholders("Tänään uutisissa.", nil)
	if err != nil || restored != "Tänään uutisissa." {
		t.Errorf("got %q, %v", restored, err)
	}
}

// The exported pair must behave identically — a caller talking to a translator
// directly should get the same protection.
func TestExportedHelpersMatchInternal(t *testing.T) {
	text := "{{.a}} and %d"
	maskedExported, tokensExported := MaskPlaceholders(text)
	maskedInternal, tokensInternal := maskPlaceholders(text)
	if maskedExported != maskedInternal || len(tokensExported) != len(tokensInternal) {
		t.Fatal("exported masking diverged from internal")
	}
	if _, err := RestorePlaceholders("[[0]] ja", tokensExported); err == nil {
		t.Fatal("exported restore accepted a dropped placeholder")
	}
}

// --- Hardening added 2026-09-07 -------------------------------------------
//
// The first masking pass protected the placeholders it knew about. These pin
// the three ways it could still let corrupted structure through.

func TestUnsupportedPrintfVerbsAreDetectedNotMasked(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want []string
	}{
		// The dangerous case: neither maskPlaceholders nor HasPlaceholders
		// sees these, so the text looks like prose all the way to the model.
		{"zero-padded width", "Day %02d of your streak", []string{"%02d"}},
		{"precision", "You scored %.2f points", []string{"%.2f"}},
		{"left-aligned width", "%-5s complete", []string{"%-5s"}},
		{"explicit arg index", "%[1]s and %[1]s again", []string{"%[1]s"}},
		{"unsupported bare verb", "id %x", []string{"%x"}},

		// Supported verbs are masked, so nothing is left to report.
		{"supported verbs", "Uses %d words like %s", nil},
		{"escaped percent", "100%% complete", nil},

		// The prose false positive the tight mask pattern exists to avoid. A
		// permissive printf grammar matches "% o" here and would corrupt it.
		{"percent in prose", "50% off today", nil},
		{"percent then punctuation", "Progress: 80%.", nil},
		{"percent at end", "Complete: 100%", nil},
		{"no placeholders at all", "Ermin has them ready.", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnsupportedPlaceholders(tc.text)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestRestoreRejectsInventedTemplateDelimiters(t *testing.T) {
	masked, tokens := maskPlaceholders(`{{if .data.lesson_title}}Pick up “{{.data.lesson_title}}”{{end}}`)
	if len(tokens) != 3 {
		t.Fatalf("expected 3 masked actions, got %d: %q", len(tokens), masked)
	}

	// The model carried every token AND wrote an action of its own. Restoring
	// this would hand text/template an {{if}} with no {{end}}, which fails the
	// whole render — and the token bookkeeping alone is perfectly happy.
	invented := `[[0]]Jatka “[[1]]”[[2]]{{if .data.extra}}`
	if _, err := restorePlaceholders(invented, tokens); err == nil {
		t.Fatal("invented {{ must be rejected")
	}

	// A clean reordering is still fine — word order differs by language and a
	// template renders correctly whichever order its actions appear in.
	reordered := `[[0]]“[[1]]” jatkuu[[2]]`
	got, err := restorePlaceholders(reordered, tokens)
	if err != nil {
		t.Fatalf("clean reorder rejected: %v", err)
	}
	if !strings.Contains(got, `{{.data.lesson_title}}`) {
		t.Errorf("placeholder not restored: %q", got)
	}
}

func TestRestoreRejectsAPlaceholderComposedByTheTranslator(t *testing.T) {
	// Source has ONE verb. The model returns the token intact but leaves a
	// stray "%" against it, which composes into a second verb after
	// restoration. Every per-token count is 1, so only a check on the OUTPUT
	// catches this.
	masked, tokens := maskPlaceholders("Uses %d words")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d: %q", len(tokens), masked)
	}

	if _, err := restorePlaceholders("Käyttää %[[0]] sanaa", tokens); err == nil {
		t.Fatal("a verb composed from a stray %% must be rejected")
	}

	if got, err := restorePlaceholders("Käyttää [[0]] sanaa", tokens); err != nil {
		t.Fatalf("clean translation rejected: %v", err)
	} else if got != "Käyttää %d sanaa" {
		t.Errorf("got %q", got)
	}
}
