package translation

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Placeholder masking.
//
// A translatable string in this codebase is often not prose: notification
// templates are Go templates full of {{...}} actions, and a few strings are
// printf formats carrying %s or %d. Sending those to a translator verbatim
// invites three failures, all seen or narrowly avoided in production:
//
//   - the model translates an identifier ({{.data.due_count}} became
//     {{.data.số_từ}} in the autotranslate context-hint bug),
//   - it mangles an {{if}}/{{else}}/{{end}} skeleton so the template no longer
//     parses,
//   - it drops a printf verb, so fmt.Sprintf renders "%!d(MISSING)".
//
// The damage is permanent because callers persist the result with
// status='approved'. comms guards against it by refusing to translate anything
// containing "{{" at all, which is safe but leaves every notification rule
// template unlocalizable forever.
//
// Masking removes the reason for that guard: swap each placeholder for a short
// token, translate the prose around it, put the placeholders back, and REFUSE
// the result if they did not all survive. A rejected translation is not a
// failure mode — callers already fall back to source text on an empty result.
//
// Placeholder-free text is untouched: zero tokens means the input is passed
// through byte-for-byte, so this changes nothing for the ordinary case.

// placeholderPattern matches the two placeholder shapes this fleet uses.
//
// The printf verb set is deliberately TIGHT — exactly the verbs that appear in
// real strings — rather than the full printf grammar. A permissive pattern
// like %[flags][width]<letter> also matches the "% o" inside "50% off" and
// would corrupt ordinary prose, which is a worse bug than the one being fixed.
var placeholderPattern = regexp.MustCompile(`\{\{.*?\}\}|%%|%[sdvqtf]`)

// maskToken is ASCII on purpose. The opus-mt backend is a subword seq2seq
// model: private-use runes or unusual symbols fall outside its vocabulary and
// come back dropped or as <unk>. Bracketed digits survive both it and the LLM
// backends.
func maskToken(i int) string { return "[[" + strconv.Itoa(i) + "]]" }

// maskTokenPattern tolerates whitespace a translator may introduce inside or
// around the brackets.
var maskTokenPattern = regexp.MustCompile(`\[\s*\[\s*(\d+)\s*\]\s*\]`)

// maskPlaceholders replaces every placeholder with an indexed token and
// returns the originals in index order. A text with no placeholders comes back
// unchanged with a nil slice, which callers use to skip restore entirely.
func maskPlaceholders(text string) (string, []string) {
	matches := placeholderPattern.FindAllString(text, -1)
	if len(matches) == 0 {
		return text, nil
	}

	tokens := make([]string, 0, len(matches))
	i := 0
	masked := placeholderPattern.ReplaceAllStringFunc(text, func(match string) string {
		tokens = append(tokens, match)
		token := maskToken(i)
		i++
		return token
	})
	return masked, tokens
}

// restorePlaceholders puts the originals back and verifies the translator
// preserved every one exactly once.
//
// Reordering is allowed and expected — word order differs by language, and a
// Go template renders correctly whichever order its actions appear in. What is
// not allowed is a token that vanished, duplicated, or came back with an index
// that was never issued. Any of those means the model rewrote structure it was
// supposed to carry, and the only safe response is to reject the whole string.
func restorePlaceholders(translated string, tokens []string) (string, error) {
	if len(tokens) == 0 {
		return translated, nil
	}

	seen := make([]int, len(tokens))
	var unknown []string

	restored := maskTokenPattern.ReplaceAllStringFunc(translated, func(match string) string {
		groups := maskTokenPattern.FindStringSubmatch(match)
		index, err := strconv.Atoi(groups[1])
		if err != nil || index < 0 || index >= len(tokens) {
			unknown = append(unknown, match)
			return match
		}
		seen[index]++
		return tokens[index]
	})

	if len(unknown) > 0 {
		return "", fmt.Errorf("translation invented placeholder tokens %s", strings.Join(unknown, ", "))
	}

	var missing, duplicated []string
	for index, count := range seen {
		switch {
		case count == 0:
			missing = append(missing, tokens[index])
		case count > 1:
			duplicated = append(duplicated, fmt.Sprintf("%s x%d", tokens[index], count))
		}
	}
	sort.Strings(missing)
	sort.Strings(duplicated)

	switch {
	case len(missing) > 0 && len(duplicated) > 0:
		return "", fmt.Errorf("translation dropped %s and duplicated %s",
			strings.Join(missing, ", "), strings.Join(duplicated, ", "))
	case len(missing) > 0:
		return "", fmt.Errorf("translation dropped placeholders %s", strings.Join(missing, ", "))
	case len(duplicated) > 0:
		return "", fmt.Errorf("translation duplicated placeholders %s", strings.Join(duplicated, ", "))
	}

	return restored, nil
}

// MaskPlaceholders and RestorePlaceholders expose the masking pair so a caller
// that talks to a translator directly — rather than through Client — can get
// the same protection instead of reimplementing it.
func MaskPlaceholders(text string) (string, []string) { return maskPlaceholders(text) }

// RestorePlaceholders returns an error when the translated text did not carry
// every placeholder through exactly once. Treat that as "translation failed"
// and fall back to the source string; do NOT persist a partial result.
func RestorePlaceholders(translated string, tokens []string) (string, error) {
	return restorePlaceholders(translated, tokens)
}

// HasPlaceholders reports whether masking would do anything for this text.
func HasPlaceholders(text string) bool { return placeholderPattern.MatchString(text) }
