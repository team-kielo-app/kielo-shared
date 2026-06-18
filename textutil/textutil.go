package textutil

import (
	"fmt"
	"strings"
)

// FirstNonEmpty returns the first string that is non-empty after trimming.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// FirstNonEmptyPtr returns a pointer to the first non-empty trimmed string,
// or nil if all values are nil or empty.
func FirstNonEmptyPtr(values ...*string) *string {
	for _, v := range values {
		if v == nil {
			continue
		}
		if trimmed := strings.TrimSpace(*v); trimmed != "" {
			result := trimmed
			return &result
		}
	}
	return nil
}

// StringValue safely dereferences a *string, returning "" for nil.
func StringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// StringPtr returns a pointer to the given string.
func StringPtr(v string) *string {
	return &v
}

// StringFromMap reads a string value from a map[string]any, trying
// each key in order. Returns "" if no key matched or the value was nil/"<nil>".
func StringFromMap(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		s := strings.TrimSpace(fmt.Sprint(raw))
		if s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}
