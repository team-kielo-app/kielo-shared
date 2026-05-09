package localization

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CacheKey produces the same cache key shape the Python RedisCacheDecorator
// uses, so cross-language services hit the same Redis entries:
//
//	loc:{provider_id}:{src}:{tgt}:{role}:{sha256(input)[:32]}
//
// `input` is `item.cache_key` when set, otherwise `item.text`. Locale
// codes are lowercased and stripped to their base (BCP-47 → "vi" out of
// "vi-VN").
func CacheKey(providerID, source, target string, item TranslationItem) string {
	digestInput := item.CacheKey
	if digestInput == "" {
		digestInput = item.Text
	}
	sum := sha256.Sum256([]byte(digestInput))
	digest := hex.EncodeToString(sum[:])[:32]

	src := baseLocale(source)
	if src == "" {
		src = "_"
	}
	tgt := baseLocale(target)
	if tgt == "" {
		tgt = "_"
	}
	role := string(item.Role)
	if role == "" {
		role = string(RolePlain)
	}
	return "loc:" + providerID + ":" + src + ":" + tgt + ":" + role + ":" + digest
}

func baseLocale(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	if base, _, found := strings.Cut(code, "-"); found {
		return base
	}
	return code
}
