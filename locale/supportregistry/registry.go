// Package supportregistry resolves UI support-locale strings via a
// single registry interface.
//
// See docs/architecture/adr-008-support-locale-adapter.md for the full
// design rationale. The two-line summary:
//
//   - Every per-locale switch ("if support == 'vi' return X") is
//     replaced by registry.Resolve(ctx, key, supportLocale).
//   - Adding a new locale becomes "add YAML entries", not "touch 30
//     files across 8 services".
//
// This package provides the core interface plus MapRegistry — the
// in-memory implementation backed by Go maps. A future
// DynamicRegistry will compose MapRegistry with a
// localization.dynamic_translations layer for runtime overrides
// (ADR-007 §4); the MapRegistry surface is the canonical contract
// that all callers code against.
package supportregistry

import (
	"context"
	"strings"
	"sync"
)

// Key uniquely identifies a translatable UI string.
//
// Convention: "<namespace>.<sub>.<value>"
//
// Namespaces in active use:
//
//   - morphology.*     grammar terminology (POS, case, number, etc.)
//   - ui.*             generic UI labels
//   - email.*          email subject/body fragments
//   - exercise.*       exercise prompts/instructions
//   - notification.*   push notification copy
//   - discovery.*      conversation discovery labels
//
// Keys are strings rather than typed enums so seed files (YAML) can
// reference them directly without a generated-code step. The trade-off
// (no compile-time typo check at the call site) is acceptable because
// callers always reference the constants exported by each domain's
// keys.go file.
type Key string

// Registry is the single contract for resolving support-locale strings.
//
// All implementations MUST satisfy:
//
//  1. Resolve returns a non-empty string for every supportLocale in
//     SupportedLocales(). If the requested key has no localization for
//     supportLocale, the registry falls through to the English seed.
//     If even English is missing, the implementation returns the key
//     itself (never empty, never the source learning-language text).
//
//  2. Resolve is safe for concurrent calls.
//
//  3. ResolveTemplate applies Go text/template substitution after
//     Resolve. Templates that fail to parse return the literal
//     resolved string (best-effort degrade).
type Registry interface {
	Resolve(ctx context.Context, key Key, supportLocale string) string
	ResolveTemplate(ctx context.Context, key Key, supportLocale string, params map[string]any) string
	SupportedLocales() []string
	CoverageReport() map[string]CoverageStats
}

// CoverageStats describes how complete a locale's seed coverage is.
// Used by both an admin UI and CI gates.
type CoverageStats struct {
	Total      int // total registered keys
	Localized  int // keys with a non-English seed for this locale
	Overridden int // keys with a runtime override in dynamic_translations
	Fallback   int // keys where this locale falls through to English
}

// FallbackLocale is the universal last-resort seed locale. Resolve
// returns the English seed whenever the requested supportLocale has
// no entry for the key. English ALWAYS has a seed — registries with
// missing English entries are rejected by ValidateSeed.
const FallbackLocale = "en"

// MapRegistry is the in-memory Registry backed by a static map.
//
// Concurrent-safe for reads. Seeds are loaded once via Set or
// LoadSeed; callers SHOULD finalize the registry (call Finalize) at
// service startup so any further Set calls fail loud.
type MapRegistry struct {
	mu        sync.RWMutex
	seeds     map[Key]map[string]string // key → locale → text
	supported []string                  // supported locales, including FallbackLocale
	finalized bool
}

// New constructs an empty MapRegistry. supportedLocales MUST include
// FallbackLocale; if not, it is appended.
func New(supportedLocales []string) *MapRegistry {
	hasEN := false
	for _, l := range supportedLocales {
		if l == FallbackLocale {
			hasEN = true
			break
		}
	}
	finalized := make([]string, 0, len(supportedLocales)+1)
	finalized = append(finalized, supportedLocales...)
	if !hasEN {
		finalized = append(finalized, FallbackLocale)
	}
	return &MapRegistry{
		seeds:     make(map[Key]map[string]string),
		supported: finalized,
	}
}

// Set registers a localization for (key, supportLocale). MUST be called
// before Finalize. Repeated calls for the same (key, locale) overwrite.
//
// Returns false if the registry was already finalized — callers should
// treat this as a startup bug.
func (r *MapRegistry) Set(key Key, supportLocale, text string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized {
		return false
	}
	if r.seeds[key] == nil {
		r.seeds[key] = make(map[string]string)
	}
	r.seeds[key][normalize(supportLocale)] = text
	return true
}

// Finalize marks the registry read-only. Subsequent Set calls return
// false. Call this at the end of service startup so test reloads or
// late hot-patches fail loud.
func (r *MapRegistry) Finalize() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finalized = true
}

// Resolve implements Registry.
func (r *MapRegistry) Resolve(_ context.Context, key Key, supportLocale string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries, ok := r.seeds[key]
	if !ok {
		return string(key)
	}
	if text, ok := entries[normalize(supportLocale)]; ok && text != "" {
		return text
	}
	if text, ok := entries[FallbackLocale]; ok && text != "" {
		return text
	}
	return string(key)
}

// ResolveTemplate implements Registry. Templates use Go's text/template
// syntax: "Hello {{.Name}}" + {Name:"x"} → "Hello x". A malformed
// template OR a missing parameter returns the literal Resolve result
// (best-effort degrade rather than crashing the caller).
func (r *MapRegistry) ResolveTemplate(ctx context.Context, key Key, supportLocale string, params map[string]any) string {
	text := r.Resolve(ctx, key, supportLocale)
	if !strings.Contains(text, "{{") {
		return text
	}
	return applyTemplate(text, params)
}

// SupportedLocales implements Registry.
func (r *MapRegistry) SupportedLocales() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.supported))
	copy(out, r.supported)
	return out
}

// CoverageReport implements Registry.
//
// For MapRegistry, Overridden is always 0 — overrides come from a
// future DynamicRegistry composed on top. Fallback counts keys whose
// requested locale falls through to English.
func (r *MapRegistry) CoverageReport() map[string]CoverageStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]CoverageStats, len(r.supported))
	for _, locale := range r.supported {
		var stats CoverageStats
		for _, entries := range r.seeds {
			stats.Total++
			if _, ok := entries[locale]; ok {
				stats.Localized++
			} else if _, ok := entries[FallbackLocale]; ok {
				stats.Fallback++
			}
		}
		out[locale] = stats
	}
	return out
}

func normalize(locale string) string {
	return strings.ToLower(strings.TrimSpace(locale))
}
