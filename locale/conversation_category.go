package locale

import "strings"

// conversationCategoryLabels is the canonical English display label for
// each scenario category enum value used across convo + user-service.
// Keep keys in sync with the `category` column in convo.scenarios.
var conversationCategoryLabels = map[string]string{
	"everyday-life":        "Everyday life",
	"shopping-services":    "Shopping & services",
	"food-dining":          "Food & dining",
	"transport-travel":     "Transport & travel",
	"work-professional":    "Work & professional",
	"social-relationships": "Social & relationships",
	"health-wellbeing":     "Health & wellbeing",
	"education-learning":   "Education & learning",
	"finnish-society":      "Finnish society & bureaucracy",
	"culture-leisure":      "Culture & leisure",
	"digital-modern":       "Digital & modern life",
	"advanced-real-life":   "Advanced / real-life",
	"other":                "Other",
}

// conversationCategoryLabelsByLocale is the per-locale translation
// registry. English (the canonical source) lives in
// conversationCategoryLabels and is intentionally not duplicated here —
// the lookup falls back to it when a locale-specific entry is missing.
var conversationCategoryLabelsByLocale = map[string]map[string]string{
	"vi": {
		"everyday-life":        "Đời sống hàng ngày",
		"shopping-services":    "Mua sắm & dịch vụ",
		"food-dining":          "Ẩm thực & ăn uống",
		"transport-travel":     "Giao thông & du lịch",
		"work-professional":    "Công việc & nghề nghiệp",
		"social-relationships": "Xã hội & quan hệ",
		"health-wellbeing":     "Sức khỏe & thể chất",
		"education-learning":   "Giáo dục & học tập",
		"finnish-society":      "Xã hội & hành chính Phần Lan",
		"culture-leisure":      "Văn hóa & giải trí",
		"digital-modern":       "Cuộc sống số & hiện đại",
		"advanced-real-life":   "Nâng cao / thực tế",
		"other":                "Khác",
	},
}

// ConversationCategoryLabel returns the human-readable label for a
// scenario category enum value in the requested support locale.
// Resolution order: (1) per-locale registry, (2) canonical English,
// (3) auto-titlecased fallback from the key itself. Never returns an
// empty string for non-empty input — facet rendering depends on this.
func ConversationCategoryLabel(key, supportLocale string) string {
	if key == "" {
		return ""
	}
	if normalized := NormalizeLocaleCode(supportLocale); normalized != "" && normalized != TierASupportLocale {
		if table, ok := conversationCategoryLabelsByLocale[normalized]; ok {
			if label, ok := table[key]; ok && strings.TrimSpace(label) != "" {
				return label
			}
		}
	}
	if label, ok := conversationCategoryLabels[key]; ok {
		return label
	}
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
// scenario browse bucket keys ("main", "other"). Same fallback chain
// semantics as ConversationCategoryLabel.
func ConversationBucketLabel(key, supportLocale string) string {
	if NormalizeLocaleCode(supportLocale) == "vi" {
		switch key {
		case "main":
			return "Chính"
		case "other":
			return "Khác"
		}
	}
	switch key {
	case "main":
		return "Main"
	case "other":
		return "Other"
	}
	return key
}
