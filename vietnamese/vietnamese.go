// Package vietnamese provides hand-verified translation overrides for
// common Finnish learning terms.
//
// Two distinct concerns live here, kept in one package because they're
// all small lookup tables used by the same dictionary lookup path:
//
//  1. SUPPORT-LOCALE TRANSLATIONS (ADR-008 supportregistry):
//     Glossary and grammar-concept overrides keyed on English /
//     canonical-name → per-locale value. These live in
//     `dictionaryRegistry` and are accessed via:
//
//     - GlossOverrideFor(value, supportLocale)
//     - GrammarConceptOverrideFor(value, supportLocale)
//
//     Adding a new support locale = adding seeds, not touching call
//     sites — exactly the ADR-008 contract.
//
//  2. LEARNING-LANGUAGE → LEARNING-LANGUAGE NORMALIZATION:
//     `DictionaryTermOverride` (Finnish pronoun → VI gloss) and
//     `KnownLemmaOverride` (FI → canonical FI lemma) operate on
//     Finnish surface forms, not English keys. They do NOT fit the
//     supportregistry contract (the registry is for English-keyed
//     support-locale lookups, not for learning-language helpers), so
//     they stay as plain maps.
//
//     DictionaryTermOverride could in principle be re-keyed on
//     English and migrated, but the resulting registry would have a
//     7-entry duplicate of GlossOverrideFor's pronoun rows and the
//     caller would still need a Finnish → English lookup step
//     elsewhere. Net negative.
//
// The deprecated single-locale-VI wrappers
// (DictionaryGlossOverride, GrammarConceptFallback) remain for one
// release cycle so external callers can migrate. Internal call sites
// should use the *For / *OverrideFor variants directly.
package vietnamese

import (
	"context"
	"strings"
	"sync"

	"github.com/team-kielo-app/kielo-shared/locale"
	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// dictionarySeed is the ADR-008 supportregistry holding the
// English-keyed gloss + grammar-concept overrides. Constructed once at
// package init and Finalize()d so any drift in seeds during runtime
// fails loud.
//
// Key namespaces:
//
//   - vi.dict.gloss.<lower-cased-english>      gloss overrides
//   - vi.dict.grammar.<canonical-grammar-name> grammar concept overrides
//     (case-preserved; see case-sensitivity note below)
//
// Locales seeded: en (canonical / identity) + vi (override).
//
// Case-sensitivity contract preserved from the pre-registry impl:
//
//   - gloss keys are lower-cased on insertion and on lookup. "TRAIN"
//     and "train" both resolve.
//   - grammar keys are NOT lower-cased. "Preesens" resolves; "preesens"
//     does not. This is intentional — grammar concept names are
//     canonical tokens, not free text, and a lowercase variant likely
//     indicates the caller passed a generic word.
//
// Round 6 (2026-06-09 C3): wrapped with dynamicregistry via the
// consumer-side SetDictionaryRegistry hook so admins can curate
// non-vi gloss + grammar-concept translations
// (resource_type='ui.string') via the kielo-localization admin UI.
// The pre-Round-6 pattern hard-coded vi-only; admin curation for
// other support locales (pt, ja, ko, ...) required a code change +
// redeploy. IMPORTANT: this file does NOT import dynamicregistry —
// that would create an import cycle (dynamicregistry imports locale
// for ResourceTypeUIString). Init is consumer-side; this package
// only exposes the SEED + SET hooks. Mirrors the canonical
// SetConversationCategoryRegistry pattern at
// kielo-shared/locale/conversation_category.go.
var dictionarySeed = func() *supportregistry.MapRegistry {
	// Round 6 C6 (2026-06-09): widened from {en, vi} hardcoded to
	// the platform-wide locale set. Seed entries below only populate
	// en + vi; SupportedLocales() now reports all 23 platform locales,
	// so admin UI for kielo-localization will surface every locale
	// as curatable.
	r := supportregistry.New(locale.AllSupportLocales())

	// Glosses: English phrase → VI translation. Key is lower-cased
	// (consistent with the previous glossOverrides[strings.ToLower(...)]
	// lookup). English seed is the phrase itself (identity), which
	// becomes the natural fallback for non-VI support locales.
	//
	// NOTE on "you (plural)" vs "you": Finnish distinguishes singular
	// "sinä" from plural "te"; English collapses both to "you". To
	// preserve the pre-registry VI plural form ("các bạn/quý vị") for
	// "te" without conflating it with singular "sinä", we register an
	// explicit "you (plural)" key — the FI→EN map in
	// finnishPronounToEnglish below routes "te" to it.
	for _, e := range []struct {
		en string
		vi string
	}{
		{"I", "tôi"},
		{"me", "tôi"},
		{"you", "bạn"},
		{"you (plural)", "các bạn/quý vị"},
		{"for you / to you", "cho bạn"},
		{"he/she", "anh ấy/cô ấy"},
		{"he / she", "anh ấy/cô ấy"},
		{"it", "nó"},
		{"we", "chúng tôi/chúng ta"},
		{"they", "họ"},
		{"to be", "là"},
		{"shop, store", "cửa hàng, tiệm"},
		{"train", "tàu hỏa"},
	} {
		key := glossKey(e.en)
		r.Set(key, "en", e.en)
	}

	// Grammar concepts: case-sensitive canonical name → VI translation.
	// Two sets of keys (Finnish + English forms) intentionally map to
	// the same VI value — callers may pass either depending on origin.
	for _, e := range []struct {
		canonical string
		vi        string
	}{
		{"Genetiivi (-n)", "cách sở hữu"},
		{"Genitive Case", "cách sở hữu"},
		{"Genitive", "sở hữu"},
		{"Partitiivi", "cách bộ phận"},
		{"Partitive Case", "cách bộ phận"},
		{"Imperatiivi", "thức mệnh lệnh"},
		{"Imperative Mood", "thức mệnh lệnh"},
		{"Preesens", "thì hiện tại"},
		{"Present Tense", "thì hiện tại"},
		{"Perfekti", "thì hoàn thành"},
		{"Perfect Tense", "thì hoàn thành"},
		{"Imperfekti", "thì quá khứ"},
		{"Past Tense", "thì quá khứ"},
	} {
		key := grammarKey(e.canonical)
		r.Set(key, "en", e.canonical)
	}

	r.Finalize()
	return r
}()

// DictionarySeed returns the finalized in-memory MapRegistry holding
// the canonical English source-of-truth + vi hand-curated translations
// for gloss + grammar-concept overrides.
//
// Consumers (kielo-content-service main.go, kielo-user-service
// main.go) call this + pass it to dynamicregistry.New(seed, pool,
// cache) + register the resulting wrapper via
// SetDictionaryRegistry. Round 6 (2026-06-09 C3).
//
// Exposed so tests + offline callers (admin scripts) can resolve
// directly against the seed without DB/Redis dependencies.
func DictionarySeed() supportregistry.Registry {
	return dictionarySeed
}

// dictionaryRegistry is the registry callers Resolve() against. At
// package load it points to the seed-only MapRegistry; consumers
// (kielo-content-service, kielo-user-service) call
// SetDictionaryRegistry(wrapped) at startup to swap in a
// dynamicregistry.Registry that consults
// localization.dynamic_translations on every Resolve.
//
// Concurrent-safe via RWMutex (defensive — production reads happen
// after the swap, which happens once at startup).
var (
	dictionaryRegistryMu sync.RWMutex
	dictionaryRegistry   supportregistry.Registry = dictionarySeed
)

// SetDictionaryRegistry swaps in a caller-constructed
// dynamicregistry-wrapped registry. The seed registry is preserved
// as fallback. nil is a no-op (preserves current registry).
//
// MUST be called from main.go BEFORE any handler is registered.
// Mirrors the canonical SetConversationCategoryRegistry shape.
// Round 6 (2026-06-09 C3).
func SetDictionaryRegistry(r supportregistry.Registry) {
	if r == nil {
		return
	}
	dictionaryRegistryMu.Lock()
	dictionaryRegistry = r
	dictionaryRegistryMu.Unlock()
}

// resolveDictionary is the single read-path the package's public
// helpers funnel through. Centralizes the RWMutex acquisition so
// callers don't have to think about the swap-at-startup race.
func resolveDictionary(ctx context.Context, key supportregistry.Key, supportLocale string) string {
	dictionaryRegistryMu.RLock()
	r := dictionaryRegistry
	dictionaryRegistryMu.RUnlock()
	return r.Resolve(ctx, key, supportLocale)
}

func glossKey(english string) supportregistry.Key {
	return supportregistry.Key("vi.dict.gloss." + strings.ToLower(strings.TrimSpace(english)))
}

func grammarKey(canonical string) supportregistry.Key {
	return supportregistry.Key("vi.dict.grammar." + strings.TrimSpace(canonical))
}

// GlossOverrideFor returns the support-locale translation for a common
// English gloss, or "" if no seed exists for the value.
//
// Resolution: per-locale seed → English fallback → "" (NOT the key
// string, which would be cosmetically wrong for a gloss override).
//
// Callers should pass the user's support locale, not hard-code "vi".
func GlossOverrideFor(value, supportLocale string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	key := glossKey(value)
	got := resolveDictionary(context.Background(), key, supportLocale)
	if got == string(key) {
		// Registry miss: no seed at all for this gloss. Returning ""
		// preserves the pre-registry contract where missing entries
		// fell through to the upstream translator path.
		return ""
	}
	return got
}

// GrammarConceptOverrideFor returns the support-locale translation for
// a canonical grammar concept name (Finnish or English form), or "" if
// no seed exists.
//
// Case-sensitive (see note on dictionaryRegistry above). Resolution
// order matches GlossOverrideFor.
func GrammarConceptOverrideFor(value, supportLocale string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	key := grammarKey(value)
	got := resolveDictionary(context.Background(), key, supportLocale)
	if got == string(key) {
		return ""
	}
	return got
}

// DictionaryGlossOverride / GrammarConceptFallback / DictionaryTermOverride
// were the VI-hardcoded wrappers around the ADR-008 supportregistry
// helpers. Removed 2026-05-17 once every production caller had
// migrated to GlossOverrideFor / GrammarConceptOverrideFor /
// TermOverrideFor (which take the user's support locale instead of
// pinning it to "vi"). Test coverage moved to the *_For variants;
// see vietnamese_test.go for the new pinning shape.

// TermOverrideFor returns the support-locale translation for a Finnish
// pronoun / common term (e.g. for term="minä", supportLocale="vi"
// returns "tôi"; for supportLocale="en" returns "I"; for unsupported
// locales falls back to the English form).
//
// Resolution path:
//
//  1. Normalize the Finnish input (lowercased, trimmed).
//  2. Map FI → canonical English via finnishPronounToEnglish.
//  3. Resolve English → supportLocale via GlossOverrideFor (which goes
//     through the ADR-008 supportregistry).
//
// Returns "" if the input isn't a known Finnish pronoun, OR if no seed
// exists for the resolved English key (defensive — should never
// happen as long as the two maps stay in sync; covered by
// TestTermOverrideFor_FiPronounsHaveCorrespondingGlossSeeds).
func TermOverrideFor(term, supportLocale string) string {
	english, ok := finnishPronounToEnglish[strings.ToLower(strings.TrimSpace(term))]
	if !ok {
		return ""
	}
	return GlossOverrideFor(english, supportLocale)
}

// finnishPronounToEnglish maps the same FI keys as termOverrides above
// to their canonical English form, which is then resolved through the
// supportregistry. Kept as a separate map (rather than refactoring
// termOverrides) so the deprecated DictionaryTermOverride keeps its
// original VI-direct semantics for one release cycle.
//
// MUST stay in sync with termOverrides: every termOverrides key MUST
// appear here with an English value that corresponds to a glossKey
// seed. The TestTermOverrideFor_FiPronounsHaveCorrespondingGlossSeeds
// test enforces this invariant.
var finnishPronounToEnglish = map[string]string{
	"minä": "I",
	"sinä": "you",
	"hän":  "he/she",
	"se":   "it",
	"me":   "we",
	"te":   "you (plural)",
	"he":   "they",
}

// KnownLemmaOverride returns the canonical lemma for Finnish pronouns
// that morphology APIs may not handle correctly, or "" if not a known
// override.
//
// NOT migrated to supportregistry: this is a learning-language →
// learning-language identity helper, not a support-locale lookup.
// See package doc.
func KnownLemmaOverride(term string) string {
	return knownLemmas[strings.ToLower(strings.TrimSpace(term))]
}

var termOverrides = map[string]string{
	"minä": "tôi",
	"sinä": "bạn",
	"hän":  "anh ấy/cô ấy",
	"se":   "nó",
	"me":   "chúng tôi/chúng ta",
	"te":   "các bạn/quý vị",
	"he":   "họ",
}

var knownLemmas = map[string]string{
	"minä": "minä",
	"sinä": "sinä",
	"hän":  "hän",
	"se":   "se",
	"me":   "me",
	"te":   "te",
	"he":   "he",
}
