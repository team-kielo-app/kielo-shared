package locale

import (
	"context"
	"strings"
	"sync"

	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// Conversation category + bucket localization.
//
// Storage model
// -------------
//
// The canonical English source-of-truth + vi hand-curated translations
// live in the seed MapRegistry (conversationCategorySeed below). Going
// to a NEW locale (pt, ja, ko, ru, fr, de, ...) does NOT require a Go
// code change: admins curate the long tail via the kielo-localization
// admin UI for resource_type='ui.string',
// resource_id='ui.conversation.category.<key>', language_code='<new>'.
//
// The dynamicregistry layer picks up admin overrides on the next
// Resolve (cached behind Redis with default 5min TTL). Activated by
// callers via SetConversationCategoryRegistry(dynamic) — typically
// from kielo-user-service main.go AND kielo-convo orchestrator main.go.
//
// IMPORTANT: This file does NOT import dynamicregistry — that would
// create an import cycle (dynamicregistry imports locale for
// ResourceTypeUIString). Init is consumer-side; this package only
// exposes the SEED + SET hooks.
//
// HIGH-TRAFFIC locales that should ship hand-curated at code time
// stay here as seed entries — the dynamic layer is a SECOND chance
// to override, not a replacement.

// ConversationCategorySeed returns the finalized in-memory MapRegistry
// holding the canonical en source-of-truth + vi hand-curated
// translations for category and bucket labels.
//
// Consumers (kielo-user-service, kielo-convo orchestrator) call this
// + pass it to dynamicregistry.New(seed, pool, cache) + register the
// resulting wrapper via SetConversationCategoryRegistry.
//
// Exposed so tests + offline callers (admin scripts) can resolve
// directly against the seed without DB/Redis dependencies.
func ConversationCategorySeed() supportregistry.Registry {
	return conversationCategorySeed
}

var conversationCategorySeed = buildConversationCategorySeed()

func buildConversationCategorySeed() *supportregistry.MapRegistry {
	// Round 6 C6 (2026-06-09): widened from {en, vi} hardcoded to
	// the platform-wide locale set. Seed entries below only populate
	// en + vi; SupportedLocales() now reports all 23, so admin UI
	// for kielo-localization will surface every platform locale as
	// curatable (vs blocking on a code change to add ar/pt/ja/...).
	r := supportregistry.New(AllSupportLocales())

	for _, e := range []struct {
		categoryKey string
		en          string
		vi          string
	}{
		{"everyday-life", "Everyday life", "Đời sống hàng ngày"},
		{"shopping-services", "Shopping & services", "Mua sắm & dịch vụ"},
		{"food-dining", "Food & dining", "Ẩm thực & ăn uống"},
		{"transport-travel", "Transport & travel", "Giao thông & du lịch"},
		{"work-professional", "Work & professional", "Công việc & nghề nghiệp"},
		{"social-relationships", "Social & relationships", "Xã hội & quan hệ"},
		{"health-wellbeing", "Health & wellbeing", "Sức khỏe & thể chất"},
		{"education-learning", "Education & learning", "Giáo dục & học tập"},
		{"finnish-society", "Finnish society & bureaucracy", "Xã hội & hành chính Phần Lan"},
		{"culture-leisure", "Culture & leisure", "Văn hóa & giải trí"},
		{"digital-modern", "Digital & modern life", "Cuộc sống số & hiện đại"},
		{"advanced-real-life", "Advanced / real-life", "Nâng cao / thực tế"},
		{"other", "Other", "Khác"},
	} {
		key := supportregistry.Key("ui.conversation.category." + e.categoryKey)
		r.Set(key, "en", e.en)
		r.Set(key, "vi", e.vi)
	}

	for _, e := range []struct {
		bucketKey string
		en        string
		vi        string
	}{
		{"main", "Main", "Chính"},
		{"other", "Other", "Khác"},
	} {
		key := supportregistry.Key("ui.conversation.bucket." + e.bucketKey)
		r.Set(key, "en", e.en)
		r.Set(key, "vi", e.vi)
	}

	r.Finalize()
	return r
}

// conversationCategoryRegistry is the registry callers resolve
// against. At package load it points to the seed-only MapRegistry;
// consumers (kielo-user-service, kielo-convo orchestrator) call
// SetConversationCategoryRegistry(wrapped) at startup to swap in a
// dynamicregistry.Registry that consults
// localization.dynamic_translations (resource_type='ui.string').
//
// Concurrent-safe: MapRegistry / dynamicregistry.Registry are
// themselves safe. The RWMutex defends only against test re-init.
var (
	conversationCategoryRegistryMu sync.RWMutex
	conversationCategoryRegistry   supportregistry.Registry = conversationCategorySeed
)

// SetConversationCategoryRegistry swaps the active registry with the
// supplied one (typically a dynamicregistry.Registry wrapping the
// seed). Idempotent — calling twice replaces the registry; tests use
// this to inject seed-only behavior.
//
// MUST be called from main.go BEFORE any handler is registered. Both
// kielo-user-service and kielo-convo orchestrator should call this.
// Failure to call from one side means that surface only sees the
// in-memory seed (en + vi) — no breakage, just a missed
// dynamic-override opportunity.
//
// Nil registry argument is a no-op (defensive).
func SetConversationCategoryRegistry(r supportregistry.Registry) {
	if r == nil {
		return
	}
	conversationCategoryRegistryMu.Lock()
	conversationCategoryRegistry = r
	conversationCategoryRegistryMu.Unlock()
}

// resolveConversationCategory is the single read-path the package's
// public helpers funnel through. Centralizes the RWMutex acquisition
// so callers don't have to think about the swap-at-startup race.
func resolveConversationCategory(ctx context.Context, key supportregistry.Key, supportLocale string) string {
	conversationCategoryRegistryMu.RLock()
	r := conversationCategoryRegistry
	conversationCategoryRegistryMu.RUnlock()
	return r.Resolve(ctx, key, NormalizeLocaleCode(supportLocale))
}

// ConversationCategoryLabel returns the human-readable label for a
// scenario category enum value in the requested support locale.
//
// Resolution order:
//
//  1. Per-request DB probe against localization.dynamic_translations
//     for resource_type='ui.string' (cached). Admin-curated overrides
//     win. Active after main.go calls SetConversationCategoryRegistry
//     with a dynamicregistry-wrapped registry.
//  2. Seed: vi (hand-curated in code).
//  3. Seed: en (canonical source).
//  4. Auto-titlecased reformat of the key itself ("foo-bar" → "Foo Bar").
//
// Step 4 is the registry's "unknown key" tail: the registry returns
// the key string verbatim on miss, and we detect that to apply the
// auto-titlecase prettifier rather than showing the user the raw
// "ui.conversation.category.<key>" namespace.
//
// Never returns an empty string for non-empty input — facet rendering
// in the convo browse UI depends on this contract.
func ConversationCategoryLabel(key, supportLocale string) string {
	if key == "" {
		return ""
	}
	resolveKey := supportregistry.Key("ui.conversation.category." + key)
	got := resolveConversationCategory(context.Background(), resolveKey, supportLocale)
	if got != string(resolveKey) {
		// Registry found a seed (per-locale, English fallback, OR an
		// admin-curated override via dynamicregistry).
		return got
	}
	// Registry miss: produce the auto-titlecased prettifier the
	// pre-registry implementation used. "advanced_real-life" →
	// "Advanced Real Life".
	parts := strings.Split(strings.ReplaceAll(key, "_", "-"), "-")
	for idx, part := range parts {
		if part == "" {
			continue
		}
		parts[idx] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

// ConversationBucketLabel returns the human-readable label for the
// scenario browse bucket keys ("main", "other"). Unknown keys pass
// through unchanged — buckets are a closed set, an unknown one is a
// caller bug, not a UI rendering problem.
func ConversationBucketLabel(key, supportLocale string) string {
	if key == "" {
		return ""
	}
	resolveKey := supportregistry.Key("ui.conversation.bucket." + key)
	got := resolveConversationCategory(context.Background(), resolveKey, supportLocale)
	if got != string(resolveKey) {
		return got
	}
	return key
}
