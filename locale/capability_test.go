package locale

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupCapability_HappyPath(t *testing.T) {
	fi, ok := LookupCapability("fi")
	assert.True(t, ok)
	assert.NotNil(t, fi)
	assert.Equal(t, "fi", fi.Code)
	assert.Equal(t, "Finnish", fi.Display.DisplayNameEn)
	assert.Equal(t, "Finland", fi.Display.CountryContext)
	assert.Equal(t, "voikko", fi.Morphology.PrimaryBackend)
	assert.True(t, fi.Morphology.HasParadigmGenerator)
	assert.Equal(t, "fi_core_news_sm", fi.Morphology.SpacyPipeline)
	assert.Contains(t, fi.Morphology.ExclusiveCases, "partitive")
	assert.Equal(t, "fi", fi.STT.WhisperLanguageTag)
	assert.NotEmpty(t, fi.Prompts.OfflineTranslationFallbacks)

	sv, ok := LookupCapability("sv")
	assert.True(t, ok)
	assert.NotNil(t, sv)
	assert.Equal(t, "sv", sv.Code)
	assert.Equal(t, "Swedish", sv.Display.DisplayNameEn)
	assert.Equal(t, "swedish_morphology", sv.Morphology.PrimaryBackend)
	assert.Equal(t, "swedish_morphology", sv.Morphology.LocalFallbackModule)
	assert.Empty(t, sv.Morphology.ExclusiveCases)
	assert.Empty(t, sv.Prompts.OfflineTranslationFallbacks,
		"sv has no offline translation fallback dict yet")
}

func TestLookupCapability_NormalizesAliases(t *testing.T) {
	// "sv-SE" → "sv"
	entry, ok := LookupCapability("sv-SE")
	assert.True(t, ok)
	assert.Equal(t, "sv", entry.Code)

	// "fi_FI" → "fi"
	entry, ok = LookupCapability("fi_FI")
	assert.True(t, ok)
	assert.Equal(t, "fi", entry.Code)
}

func TestLookupCapability_RejectsUnsupported(t *testing.T) {
	// Localization-only locale ("vi") is NOT an authored learning
	// language. Capability lookup returns (nil, false) per Phase 10C
	// no-silent-fallback contract.
	entry, ok := LookupCapability("vi")
	assert.False(t, ok)
	assert.Nil(t, entry)

	entry, ok = LookupCapability("")
	assert.False(t, ok)
	assert.Nil(t, entry)

	entry, ok = LookupCapability("garbage")
	assert.False(t, ok)
	assert.Nil(t, entry)
}

func TestSupportedCapabilities_CoversSupportedLearningLanguages(t *testing.T) {
	// Every code in SupportedLearningLanguages() must have a
	// capability record. The reverse must also hold — adding a row
	// to capabilities map must also extend the supported-languages
	// set. This test catches drift between the two.
	caps := SupportedCapabilities()
	supported := SupportedLearningLanguages()

	assert.Equal(t, len(supported), len(caps),
		"len mismatch: SupportedLearningLanguages=%v capabilities=%d",
		supported, len(caps))

	got := make(map[string]bool, len(caps))
	for _, entry := range caps {
		got[entry.Code] = true
	}
	for _, code := range supported {
		assert.True(t, got[code],
			"supported language %q has no capability record", code)
	}
}

func TestSupportedCapabilities_OrderMatchesSupportedLearningLanguages(t *testing.T) {
	// Order must be deterministic for fan-out scripts (admin tooling,
	// migration runners). SupportedLearningLanguages() guarantees
	// alphabetical order; SupportedCapabilities mirrors it.
	caps := SupportedCapabilities()
	supported := SupportedLearningLanguages()
	for i, entry := range caps {
		assert.Equal(t, supported[i], entry.Code,
			"index %d: entry.Code=%q supported=%q", i, entry.Code, supported[i])
	}
}

func TestCapability_DisplayNameMatchesSharedDisplayName(t *testing.T) {
	// DisplayCapability.DisplayNameEn must match locale.DisplayName(code).
	// Otherwise a registry lookup returns one name and the shared helper
	// returns another — drift hazard for any UI text that mixes both.
	for _, entry := range SupportedCapabilities() {
		shared := DisplayName(entry.Code, "")
		assert.Equal(t, shared, entry.Display.DisplayNameEn,
			"capability[%q].Display.DisplayNameEn=%q but DisplayName(%q)=%q",
			entry.Code, entry.Display.DisplayNameEn, entry.Code, shared)
	}
}

func TestCapability_AllFieldsAreNonEmptyForRequiredSlots(t *testing.T) {
	// Required-slot policy from the scoping report §C.3:
	//   - Code: required
	//   - Display.DisplayNameEn: required
	//   - Morphology.PrimaryBackend: required
	//   - Morphology.HasParadigmGenerator: required (boolean, always set)
	//   - STT.WhisperLanguageTag: required
	for _, entry := range SupportedCapabilities() {
		assert.NotEmpty(t, entry.Code, "Code is required")
		assert.NotEmpty(t, entry.Display.DisplayNameEn,
			"Display.DisplayNameEn is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Morphology.PrimaryBackend,
			"Morphology.PrimaryBackend is required for %q", entry.Code)
		assert.NotEmpty(t, entry.STT.WhisperLanguageTag,
			"STT.WhisperLanguageTag is required for %q", entry.Code)
	}
}
