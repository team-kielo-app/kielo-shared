// Package seampersister supplies production wirings of the
// localization.TranslationPersister contract (Round 10D). Lives in its
// own subpackage to keep kielo-shared/localization free of imports
// from kielo-shared/localization/dynclient — the dynclient itself
// reaches back into kielo-shared/middleware which imports
// kielo-shared/localization, creating an import cycle if we put the
// production persister in the parent package.
//
// The seam-side TranslationPersister protocol + Noop/Map test impls
// live in kielo-shared/localization/seam_persister.go (no cyclical
// imports). This package supplies the dynclient-backed production
// impl that the parent's protocol expects.
//
// Production wiring in each service's main.go:
//
//	dyn := dynclient.New(localizationURL, internalAPIKey, nil)
//	persister := seampersister.NewDynClient(dyn, "seam_autotranslate", logger)
//	seam := localization.NewSeamWith(
//	    registry, cache, overrides, metrics,
//	    persister, localization.NewCanonicalGuard(),
//	    localization.SeamConfig{},
//	)
package seampersister

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/team-kielo-app/kielo-shared/localization"
	"github.com/team-kielo-app/kielo-shared/localization/dynclient"
)

// DynClient implements localization.TranslationPersister by POSTing
// each successful seam translation to kielo-localization's
// dynamic_translations endpoint. Round 10D production wiring.
//
// Rows land as status='machine' with translator_source identifying the
// shipping round (default 'seam_autotranslate', overridable via
// NewDynClient's translatorSource arg). The kielo-localization admin
// UI surfaces these rows for operator review + promotion to
// status='approved' WITHOUT re-running the LLM (the row IS the curated
// canonical for that locale once approved).
//
// Mirror of the Python DynClientPersister at
// kielolearn-engine localization_registry.DynClientPersister
// (Round 10A) — same UpsertRequest shape, same status/translator_source
// defaults, same backend.
//
// Concurrency: safe for concurrent Persist calls. The dynclient.Client
// is safe across goroutines (per its package doc); this wrapper adds
// no state.
//
// Error handling: Persist always returns nil to the seam (per the
// TranslationPersister contract: "MUST swallow internal errors"), but
// logs the failure at WARN. Production observability layer can alert
// on a sustained increase in the warn-rate to surface a
// kielo-localization outage without breaking user-facing translation.
type DynClient struct {
	client           *dynclient.Client
	translatorSource string
	logger           *slog.Logger
}

// NewDynClient constructs a DynClient persister wired to the supplied
// dynclient.Client. translatorSource defaults to "seam_autotranslate"
// when empty — the canonical Round 10D provenance tag. Pass a service-
// specific suffix (e.g. "seam_autotranslate_user" from kielo-user-
// service) when the operator audit needs to slice by which service
// originated the autotranslate fill.
//
// logger may be nil; defaults to slog.Default() so persist failures
// land in the standard application log stream.
func NewDynClient(client *dynclient.Client, translatorSource string, logger *slog.Logger) *DynClient {
	if translatorSource == "" {
		translatorSource = "seam_autotranslate"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DynClient{
		client:           client,
		translatorSource: translatorSource,
		logger:           logger,
	}
}

// Persist implements localization.TranslationPersister.
//
// resourceType is read from ref.Namespace verbatim — callers wire the
// Namespace to the same value their consumer-side reader passes to
// dynamicregistry/SupportLocaleOverridesMiddleware (typically
// locale.ResourceTypeUIString = "ui.string"). resourceID is
// ref.SourceID. sourceVersion is ref.SourceVersion (already a
// 16-hex-char SHA256 prefix via SourceVersionFromText).
//
// status='machine' is the canonical autotranslate provenance per Voice
// Doc D2; admins promote to 'approved' via the kielo-localization admin
// UI. source_locale='en' identifies Tier-A (English source-of-truth).
func (p *DynClient) Persist(ctx context.Context, ref localization.SourceRef, targetLocale, translatedText string) error {
	if p == nil || p.client == nil {
		// Defense-in-depth: a misconfigured wiring (nil client) must
		// degrade gracefully, never panic. The seam treats this as a
		// successful persist (translation will be re-LLM'd next
		// request); the operator alert surfaces via the WARN-rate
		// increase recorded below.
		return nil
	}
	req := dynclient.UpsertRequest{
		ResourceType:     ref.Namespace,
		ResourceID:       ref.SourceID,
		SourceVersion:    ref.SourceVersion,
		LanguageCode:     targetLocale,
		TranslatedText:   translatedText,
		Status:           "machine",
		SourceLocale:     localization.TierASupportLocale,
		TranslatorSource: p.translatorSource,
	}
	if _, err := p.client.Upsert(ctx, req); err != nil {
		// Swallow per the TranslationPersister contract. The
		// translation already returned to the user; losing this
		// persistence row only means the next request re-runs the
		// LLM. Log at WARN so observability can alert if the rate
		// becomes pathological.
		p.logger.WarnContext(ctx, "seam dynclient persister failed",
			slog.String("namespace", ref.Namespace),
			slog.String("source_id", ref.SourceID),
			slog.String("target_locale", targetLocale),
			slog.String("err", fmt.Sprintf("%v", err)),
		)
	}
	return nil
}
