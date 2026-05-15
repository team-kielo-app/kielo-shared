// Package translateprovider wraps `kielo-shared/translation.Client`
// (the HTTP-to-kielo-models translation API) so it satisfies the
// `localization.Provider` interface used by the seam.
//
// Why a separate sub-package: every service that wires the seam needs
// at least one Provider, and every Go service already has the HTTP
// `translation.Client` available. This adapter lets services keep
// using the same upstream translation backend they have today, just
// behind the seam's batch + cache + override + telemetry chain.
//
// Replacement strategy when richer providers land (Gemini-direct, DeepL,
// per-locale routing): register them under their own provider IDs in
// the same registry. Existing services that wire `translateprovider`
// don't need to change — the registry routes by (source, target) and
// picks the right provider per call.
package translateprovider

import (
	"context"

	"github.com/team-kielo-app/kielo-shared/localization"
	sharedtranslation "github.com/team-kielo-app/kielo-shared/translation"
)

// Provider adapts a *sharedtranslation.Client to
// localization.Provider. The wrapped client owns connection / API key
// / retry policy; the adapter only marshals the seam's
// TranslationItem/TranslateOptions into the client's batch shape.
type Provider struct {
	client *sharedtranslation.Client
	id     string
}

// New wraps a translation.Client. providerID is what shows up in the
// seam's Provider() telemetry — convention is "<backend>:<version>"
// (e.g. "kielo-models:v1"). Callers register this id in their
// localization.Registry so route resolution can select it.
func New(client *sharedtranslation.Client, providerID string) *Provider {
	if providerID == "" {
		providerID = "kielo-models:v1"
	}
	return &Provider{client: client, id: providerID}
}

// ProviderID implements localization.Provider.
func (p *Provider) ProviderID() string {
	if p == nil {
		return ""
	}
	return p.id
}

// TranslateBatch implements localization.Provider. Maps the seam's
// items + opts onto translation.Client.TranslateBatch. The client
// returns plain strings (no per-item Provider / Cached metadata) —
// adapter fills the seam's expected TranslationResult with the wrapped
// provider ID so telemetry can attribute calls correctly.
//
// Behavior on partial failure: the underlying client returns nil when
// the whole batch fails. We surface that as `len(results) != len(items)`
// which the seam treats as a provider error and falls back to source.
// Per-item failures aren't expressible in the wrapped client's shape;
// callers that need per-item granularity should wire a richer provider.
func (p *Provider) TranslateBatch(
	ctx context.Context,
	items []localization.TranslationItem,
	opts localization.TranslateOptions,
) ([]localization.TranslationResult, error) {
	if p == nil || p.client == nil || len(items) == 0 {
		return nil, nil
	}
	texts := make([]string, len(items))
	for i, item := range items {
		texts[i] = item.Text
	}
	translated := p.client.TranslateBatch(ctx, texts, opts.SourceLocale, opts.TargetLocale)
	// Underlying client returns nil on full-batch failure — seam treats
	// that as provider_error.
	if len(translated) == 0 {
		return nil, nil
	}
	out := make([]localization.TranslationResult, len(items))
	for i := range items {
		var text string
		if i < len(translated) {
			text = translated[i]
		}
		out[i] = localization.TranslationResult{
			Text:     text,
			Provider: p.id,
		}
	}
	return out, nil
}
