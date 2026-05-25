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
	assert.Equal(t, "fi_core_news_sm", fi.Morphology.SpacyPipeline)
	assert.Contains(t, fi.Morphology.ExclusiveCases, "partitive")
	assert.True(t, fi.Morphology.HasBaseWordLookup)

	sv, ok := LookupCapability("sv")
	assert.True(t, ok)
	assert.NotNil(t, sv)
	assert.Equal(t, "sv", sv.Code)
	assert.Equal(t, "Swedish", sv.Display.DisplayNameEn)
	assert.Empty(t, sv.Morphology.ExclusiveCases)
	assert.False(t, sv.Morphology.HasBaseWordLookup)
	assert.Equal(t, []string{"rejoin_swedish_definites"}, sv.Morphology.PostLLMCleanupPasses)
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
	// Required-slot policy (post-2026-05-25 registry coverage audit):
	// only fields with at least one production consumer remain in the
	// required set. Fields without consumers (PrimaryBackend,
	// HasParadigmGenerator, LocalFallbackModule, CapitalScene,
	// DailyChallengeThemeName, PreferredVoiceID, WhisperLanguageTag,
	// DeepgramSupported, LanguageFeaturesDescription,
	// OfflineTranslationFallbacks) were deleted from the schema —
	// see the REMOVED-* comments in capability.go.
	//
	// Required-slot policy from the scoping report §C.3 (pruned):
	//   - Code: required
	//   - Display.DisplayNameEn: required (consumed by ktv_locale,
	//     admin_handler, voiceagent, nlp_utils, etc.)
	//   - Display.CountryContext: required for LLM scenario prompts
	//   - Morphology.SpacyPipeline: required (kielo-models NLP service)
	//   - Caption.SceneGreeting / SceneVerb / SceneDefault: required
	//     (kielo-cms ktv_locale.go)
	for _, entry := range SupportedCapabilities() {
		assert.NotEmpty(t, entry.Code, "Code is required")
		assert.NotEmpty(t, entry.Display.DisplayNameEn,
			"Display.DisplayNameEn is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Display.CountryContext,
			"Display.CountryContext is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Morphology.SpacyPipeline,
			"Morphology.SpacyPipeline is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Caption.SceneGreeting,
			"Caption.SceneGreeting is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Caption.SceneVerb,
			"Caption.SceneVerb is required for %q", entry.Code)
		assert.NotEmpty(t, entry.Caption.SceneDefault,
			"Caption.SceneDefault is required for %q", entry.Code)
	}
}
