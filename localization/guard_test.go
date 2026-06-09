package localization

import "testing"

// Round 10D regression tests for the canonical suspicious-translation
// guard. Each rule has a paired test case with a real-world example
// observed in production audits.
//
// Cross-language parity with the Python canonical at
// kielolearn-engine ContentLocalizer._is_suspicious_translation is
// pinned by the contract test under tests/contract/. Tests below
// validate the Go-side rule behavior in isolation.

func TestCanonicalGuard_R1_Empty(t *testing.T) {
	g := NewCanonicalGuard()
	if !g.IsSuspicious("Hello", "", "vi") {
		t.Fatal("R1: empty translation must reject")
	}
	if !g.IsSuspicious("Hello", "   ", "vi") {
		t.Fatal("R1: whitespace-only translation must reject")
	}
}

func TestCanonicalGuard_R2_TemplateLeakage(t *testing.T) {
	g := NewCanonicalGuard()
	if !g.IsSuspicious("Hello", "Xin chào %s", "vi") {
		t.Fatal("R2: %% template-leakage must reject")
	}
	if !g.IsSuspicious("Hello", "Xin chào _ban_", "vi") {
		t.Fatal("R2: underscore template-leakage must reject")
	}
}

func TestCanonicalGuard_R3a_ShortOutputFrequency(t *testing.T) {
	g := NewCanonicalGuard()
	// 9 tokens, "mới" repeats 4 times — decoder loop.
	suspect := "mới mới mới mới abc def ghi jkl mno"
	if !g.IsSuspicious("New Track New Track New Track Hello", suspect, "vi") {
		t.Fatal("R3a: short-output freq loop must reject")
	}
	// Long natural prose with normal repetition (~27 tokens, "the"
	// appears 4 times but unique > total/2 → R3a does NOT fire).
	// Source is also longer than 40 chars to avoid R4 length-blowup.
	prose := "the cat sat on the mat while a dog ran past quickly and the bird sang loudly from a tree overhead enjoying the warm summer afternoon breeze"
	longSrc := "Here is a long natural English sentence describing a quiet afternoon in the park where animals play"
	if g.IsSuspicious(longSrc, prose, "vi") {
		t.Fatal("R3a: natural prose must NOT reject")
	}
}

func TestCanonicalGuard_R3b_ConsecutiveRun(t *testing.T) {
	g := NewCanonicalGuard()
	// 4 adjacent identical tokens — canonical decoder loop sig.
	if !g.IsSuspicious("Hello world today", "very very very very nice", "vi") {
		t.Fatal("R3b: 4+ adjacent identical tokens must reject")
	}
	// 3 adjacent is acceptable (emphasis triples).
	if g.IsSuspicious("So happy today", "rất rất rất vui", "vi") {
		t.Fatal("R3b: 3-token emphasis triple must NOT reject")
	}
}

func TestCanonicalGuard_R4_LengthBlowup(t *testing.T) {
	g := NewCanonicalGuard()
	// 9-char source, 80+ char output.
	long := "This is a hallucinated paragraph the model invented from a single short word"
	if !g.IsSuspicious("Hello", long, "vi") {
		t.Fatal("R4: source <= 40 + output > 70 must reject")
	}
}

func TestCanonicalGuard_R5_ContentTokenTruncation(t *testing.T) {
	g := NewCanonicalGuard()
	// 4 content tokens → 1 target token (3:1 ratio).
	if !g.IsSuspicious("explore unfamiliar coastal beaches", "biển", "vi") {
		t.Fatal("R5: 4-content-token title → 1 target must reject")
	}
	// Phrasal-verb idiom: "pick up" (function word + 1 content) → 1
	// target. R5 must NOT fire (function words filtered out).
	if g.IsSuspicious("pick up", "nhặt", "vi") {
		t.Fatal("R5: phrasal-verb idiom must NOT reject")
	}
}

func TestCanonicalGuard_R6_JunkSymbols(t *testing.T) {
	g := NewCanonicalGuard()
	// Music note in output (Sweep PP "New Level" → "♪ Cuộc sống").
	if !g.IsSuspicious("New Level", "♪ Cuộc sống đã đến", "vi") {
		t.Fatal("R6: music-note junk in output must reject")
	}
	// Source has emoji (legitimate); output has emoji — not junk.
	if g.IsSuspicious("🎉 Welcome", "🎉 Chào mừng", "vi") {
		t.Fatal("R6: legitimate emoji must NOT reject")
	}
}

func TestCanonicalGuard_R7_NegationInjection(t *testing.T) {
	g := NewCanonicalGuard()
	// Sweep PP "pronouns" → "không có gì" (negation injection).
	if !g.IsSuspicious("pronouns", "không có gì", "vi") {
		t.Fatal("R7: vi negation injection on title-class must reject")
	}
	// Legitimate negation translation.
	if g.IsSuspicious("nothing to do", "không có gì làm", "vi") {
		t.Fatal("R7: legitimate negation source must NOT reject")
	}
}

func TestCanonicalGuard_AcceptsLegitimateTranslations(t *testing.T) {
	g := NewCanonicalGuard()
	cases := []struct {
		src, tgt, locale string
	}{
		{"Save", "Lưu", "vi"},
		{"Welcome to Kielo", "Bem-vindo ao Kielo", "pt"},
		{"Order a coffee", "Gọi một ly cà phê", "vi"},
		{"Hello", "Xin chào", "vi"},
		{"Hello", "Hej", "sv"},
		{"Hello", "こんにちは", "ja"},
		{"Today is a great day for learning Finnish", "Hôm nay là một ngày tuyệt vời để học tiếng Phần Lan", "vi"},
	}
	for _, c := range cases {
		if g.IsSuspicious(c.src, c.tgt, c.locale) {
			t.Errorf("canonical guard should NOT reject (src=%q, tgt=%q, locale=%s)", c.src, c.tgt, c.locale)
		}
	}
}
