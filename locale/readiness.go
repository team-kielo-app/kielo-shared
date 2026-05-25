package locale

// LanguageReadiness is the rolled-up "is this language production-ready?"
// view aggregated across morphology, translation, STT, NLP, and capability
// registry asset availability. Phase 13 slice 13A.
//
// Returned by GET /api/v3/readiness/learning-language/{code} (served by
// kielo-localization). Phase 14's "selectable language" UI surface
// consumes this to render the language catalog with per-language readiness
// badges; ops dashboards consume the missing_assets list to triage
// deploy regressions.
//
// Design principle: per-asset signals live in each ML service's existing
// /health response (morphology, translation, whisper, nlp). This shape
// is a roll-up VIEW — the readiness aggregator probes those health
// endpoints and synthesizes this struct. The aggregator does NOT hold
// authoritative state.
type LanguageReadiness struct {
	// Code is the normalized learning-language code (e.g. "fi", "sv").
	Code string `json:"code"`
	// DisplayName is the English name for UI rendering (sourced from
	// kielo-shared/locale.DisplayName for consistency with the
	// canonical multi-locale registry).
	DisplayName string `json:"display_name"`
	// Ready: true if every required asset (morphology + translation
	// to/from English + STT + spaCy pipeline + capability registry
	// entry) is available. False if ANY required asset is missing.
	Ready bool `json:"ready"`
	// MissingAssets enumerates which required assets are absent.
	// Empty when Ready=true. Each entry is a short asset identifier
	// (e.g. "morphology", "translation_fi_en", "whisper", "spacy",
	// "capability_registry").
	MissingAssets []string `json:"missing_assets"`
	// QualityTiers maps each asset to its quality tier — the
	// per-asset detail the morphology + translation services
	// already report (e.g. morphology="asset_backed" for fi-Voikko,
	// morphology="spacy_assisted_heuristic" for sv). Empty values
	// indicate the asset is unavailable.
	QualityTiers map[string]string `json:"quality_tiers"`
}

// LanguageReadinessProbeError is returned when a probe fails to reach
// the underlying ML service. The aggregator surfaces this as an
// asset-missing entry (rather than a transport failure) so the
// readiness response stays stable even when a downstream is briefly
// unhealthy.
type LanguageReadinessProbeError struct {
	Asset   string
	Message string
}

func (e *LanguageReadinessProbeError) Error() string {
	return "language-readiness probe (" + e.Asset + "): " + e.Message
}
