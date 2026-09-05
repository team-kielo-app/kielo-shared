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
	restored, err := restorePlaceholders("Utilise [ [ 0 ] ] mots", tokens)
	if err != nil {
		t.Fatalf("spaced token rejected: %v", err)
	}
	if restored != "Utilise %d mots" {
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
