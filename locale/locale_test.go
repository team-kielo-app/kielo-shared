package locale

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeLocaleCode(t *testing.T) {
	assert.Equal(t, "vi", NormalizeLocaleCode(" vn "))
	assert.Equal(t, "vi-VN", NormalizeLocaleCode("vi_VN"))
	assert.Equal(t, "sv-SE", NormalizeLocaleCode("sv-SE"))
	assert.Equal(t, "sv-SE", NormalizeLocaleCode("sv_se"))
	assert.Equal(t, "vi-VN", NormalizeLocaleCode("vn_vn"))
	assert.Equal(t, "zh-Hant-TW", NormalizeLocaleCode("zh-Hant-TW"))
	assert.Equal(t, "pt-BR", NormalizeLocaleCode(" pt_BR "))
	assert.Equal(t, "", NormalizeLocaleCode(""))
	assert.Equal(t, "", NormalizeLocaleCode("  "))
}

func TestNormalizeLearningLanguageCode(t *testing.T) {
	assert.Equal(t, "vi", NormalizeLearningLanguageCode(" vn "))
	assert.Equal(t, "vi", NormalizeLearningLanguageCode("vi_VN"))
	assert.Equal(t, "sv", NormalizeLearningLanguageCode("sv-SE"))
	assert.Equal(t, "sv", NormalizeLearningLanguageCode("sv_SE"))
	assert.Equal(t, "", NormalizeLearningLanguageCode(""))
}

func TestNormalizeAcceptLanguage(t *testing.T) {
	assert.Equal(t, "pt-BR", NormalizeAcceptLanguage(" pt_BR "))
	assert.Equal(t, "zh-Hant-TW", NormalizeAcceptLanguage("zh-Hant-TW,zh;q=0.9"))
	assert.Equal(t, "vi", NormalizeAcceptLanguage(" vn "))
	assert.Equal(t, "vi-VN", NormalizeAcceptLanguage("vi_VN"))
	assert.Equal(t, "de-DE", NormalizeAcceptLanguage("de-DE,de;q=0.9"))
	assert.Equal(t, "", NormalizeAcceptLanguage(""))
}
