// Sweep EEE (2026-05-30) — kielo-shared translation routing tests.
//
// Embeds the canonical fixture JSON (also consumed by the
// kielo-content-service contract test) so both Go test surfaces
// pin against the SAME Python truth table without keeping two
// copies in sync.
package translation

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed testdata/routing_fixtures.json
var routingFixturesJSON []byte

type fixtureRow struct {
	Src           string `json:"src"`
	Tgt           string `json:"tgt"`
	NSourceTokens int    `json:"n_source_tokens"`
	BackendString string `json:"backend"`
}

type fixturePayload struct {
	Comment string       `json:"_comment"`
	Rows    []fixtureRow `json:"rows"`
}

func loadFixtureRows(t *testing.T) []fixtureRow {
	t.Helper()
	var payload fixturePayload
	if err := json.Unmarshal(routingFixturesJSON, &payload); err != nil {
		t.Fatalf("decode embedded fixture: %v", err)
	}
	if len(payload.Rows) == 0 {
		t.Fatalf("embedded fixture has zero rows")
	}
	return payload.Rows
}

// TestSelectTranslatorMatchesPythonTruthTable asserts every fixture
// row's expected Backend matches what kielo-shared SelectTranslator
// returns. The same fixture is read by the kielo-content-service
// contract test; both Go test surfaces pin against the same Python
// truth table.
func TestSelectTranslatorMatchesPythonTruthTable(t *testing.T) {
	rows := loadFixtureRows(t)
	mismatches := 0
	for i, row := range rows {
		got := SelectTranslator(row.Src, row.Tgt, row.NSourceTokens)
		if got.String() != row.BackendString {
			t.Errorf(
				"row %d: SelectTranslator(%q, %q, %d) = %s; "+
					"Python truth-table says %s",
				i, row.Src, row.Tgt, row.NSourceTokens,
				got.String(), row.BackendString,
			)
			mismatches++
		}
	}
	if mismatches == 0 {
		t.Logf("OK: all %d truth-table rows match Python ↔ Go (kielo-shared)", len(rows))
	}
}

func TestNSourceTokensSpotChecks(t *testing.T) {
	cases := []struct {
		text     string
		expected int
		label    string
	}{
		{"", 0, "empty"},
		{"smyg", 1, "single token"},
		{"New Track", 2, "two tokens"},
		{"Hon smyger sig in i rummet utan att någon ser henne.", 11, "Swedish sentence"},
		{"Haluan kirjoittaa kirjeen ystävälleni.", 4, "Finnish 4-token sentence"},
		{"You have 3 lives left", 5, "mixed digit + word"},
		{"один", 1, "Cyrillic single token"},
	}
	for _, c := range cases {
		got := NSourceTokens(c.text)
		if got != c.expected {
			t.Errorf("NSourceTokens(%q) = %d; want %d (%s)", c.text, got, c.expected, c.label)
		}
	}
}

func TestSelectTranslatorBatchEndToEnd(t *testing.T) {
	cases := []struct {
		src, tgt string
		texts    []string
		expected Backend
		label    string
	}{
		{"sv", "en", []string{"smyg"}, BackendGemini, "single-token sv→en routes to Gemini (Sweep DDD)"},
		{"sv", "en", []string{"Hon smyger sig in i rummet utan att någon ser henne."}, BackendOpusMT, "sentence sv→en routes to opus-mt"},
		{"en", "vi", []string{"Hello world"}, BackendGemini, "non-high-quality pair → Gemini"},
		{"en", "en", []string{"anything"}, BackendPassthrough, "same locale → passthrough"},
		{"", "fi", []string{"anything"}, BackendPassthrough, "missing src → passthrough"},
		{"sv", "en", []string{}, BackendPassthrough, "empty batch → passthrough"},
		{"sv", "en", []string{"smyg", "a very long well-formed Swedish paragraph indeed"}, BackendGemini, "min wins: batch with short item → Gemini"},
	}
	for _, c := range cases {
		got := SelectTranslatorBatch(c.src, c.tgt, c.texts)
		if got != c.expected {
			t.Errorf("SelectTranslatorBatch(%q, %q, %v) = %s; want %s (%s)",
				c.src, c.tgt, c.texts, got, c.expected, c.label)
		}
	}
}
