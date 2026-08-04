package locale

import (
	"os"
	"regexp"
	"testing"
)

// The Go and Python locale tables are hand-mirrored, so nothing but a test
// stops them drifting. Drift here is not cosmetic: the same locale would
// normalize differently depending on whether a request is served by a Go
// service or by the engine / ingest-processor, and only one of the two would
// produce a translation-cache key that satisfies the languages foreign key.
//
// Parsed from source rather than executed so the Go suite stays hermetic
// (no Python interpreter required in the test container).
const pythonLocaleConstants = "../kielo_shared/locale_constants.py"

func TestGoPythonAliasTablesMatch(t *testing.T) {
	src, err := os.ReadFile(pythonLocaleConstants)
	if err != nil {
		t.Fatalf("cannot read the Python mirror at %s: %v", pythonLocaleConstants, err)
	}

	block := regexp.MustCompile(`(?s)LANGUAGE_CODE_ALIASES:\s*dict\[str, str\]\s*=\s*\{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("LANGUAGE_CODE_ALIASES not found in the Python mirror; " +
			"either it was renamed or the fold was removed — the two normalizers " +
			"must stay identical")
	}

	pairs := regexp.MustCompile(`"([a-z]{2,3})":\s*"([a-z]{2})"`).FindAllStringSubmatch(string(block[1]), -1)
	pythonAliases := make(map[string]string, len(pairs))
	for _, p := range pairs {
		pythonAliases[p[1]] = p[2]
	}

	if len(pythonAliases) == 0 {
		t.Fatal("parsed zero aliases from the Python mirror; the regex no longer " +
			"matches its formatting and this test would pass vacuously")
	}

	for from, to := range languageCodeAliases {
		got, ok := pythonAliases[from]
		if !ok {
			t.Errorf("alias %q -> %q exists in Go but is missing from Python", from, to)
			continue
		}
		if got != to {
			t.Errorf("alias %q: Go folds to %q, Python folds to %q", from, to, got)
		}
	}
	for from, to := range pythonAliases {
		if _, ok := languageCodeAliases[from]; !ok {
			t.Errorf("alias %q -> %q exists in Python but is missing from Go", from, to)
		}
	}
}
