package locale

import (
	"context"
	"strings"

	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// conversationCategoryRegistry holds the per-locale display labels for
// scenario category enum values. Lifted from the previous hand-rolled
// `conversationCategoryLabels` + `conversationCategoryLabelsByLocale`
// maps as part of the ADR-008 supportregistry rollout — second
// migration site after content-service/morphology_locale.go.
//
// Keys: ui.conversation.category.<enum-value>
// Locales seeded: en (canonical) + vi.
// Fallback (per Registry contract): missing locale → English seed.
//
// The `ui.conversation.bucket.*` keys cover the small browse-bucket
// labels (`main`, `other`) that previously lived in
// ConversationBucketLabel as inline switch statements.
//
// Adding a new support locale: add seed entries for every key here.
// Coverage gaps fall through to English automatically. No code
// changes elsewhere.
var conversationCategoryRegistry = func() *supportregistry.MapRegistry {
	r := supportregistry.New([]string{"en", "vi"})

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
}()

// ConversationCategoryLabel returns the human-readable label for a
// scenario category enum value in the requested support locale.
//
// Resolution order (preserved from the pre-registry implementation):
//
//  1. Per-locale seed (vi) — registry handles via Resolve.
//  2. English seed — registry falls back automatically.
//  3. Auto-titlecased reformat of the key itself ("foo-bar" → "Foo Bar").
//
// Step 3 is the registry's "unknown key" tail: the registry returns
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
	got := conversationCategoryRegistry.Resolve(context.Background(), resolveKey, NormalizeLocaleCode(supportLocale))
	if got != string(resolveKey) {
		// Registry found a seed (per-locale or English fallback).
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
	got := conversationCategoryRegistry.Resolve(context.Background(), resolveKey, NormalizeLocaleCode(supportLocale))
	if got != string(resolveKey) {
		return got
	}
	return key
}
