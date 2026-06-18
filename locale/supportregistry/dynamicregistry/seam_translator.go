package dynamicregistry

import (
	"context"

	"github.com/team-kielo-app/kielo-shared/localization"
)

// SeamTranslator adapts a localization.Seam into the Translator
// interface for Round 10D autotranslate-on-miss wiring. Calls
// seam.Translate which already runs through:
//
//  1. localization.Seam override probe (kielo-localization
//     overrides win immediately — short-circuits the LLM)
//  2. localization.Seam cache probe (Redis cache hit)
//  3. localization.Seam provider call (LLM)
//  4. localization.SuspiciousTranslationGuard (Sweep PP/QQ/KKK
//     canonical guard; rejects suspicious output)
//  5. localization.Seam cache write
//  6. localization.TranslationPersister (write-through to
//     localization.dynamic_translations as status='machine')
//
// The seam handles all the heavy lifting; SeamTranslator is the thin
// glue that lifts the seam's (SourceRef, targetLocale) →
// translatedString contract into the Translator's (resourceType,
// resourceID, sourceVersion, sourceText, targetLocale) → fire-and-
// forget contract.
//
// Production wiring example (each Go service's main.go):
//
//	persister := seampersister.NewDynClient(dynClient, "seam_autotranslate", logger)
//	guard := localization.NewCanonicalGuard()
//	seam := localization.NewSeamWith(
//	    translationRegistry, cache, overrides, metrics,
//	    persister, guard, localization.SeamConfig{},
//	)
//	translator := dynamicregistry.NewSeamTranslator(seam)
//
//	pushNotificationRegistry := dynamicregistry.New(
//	    pushNotificationSeed, pgxPool, dynregCache,
//	    dynamicregistry.WithTranslator(translator),
//	)
type SeamTranslator struct {
	seam *localization.Seam
}

// NewSeamTranslator constructs a SeamTranslator wrapping the supplied
// localization.Seam. The seam must be wired with TranslationPersister
// + SuspiciousTranslationGuard for the autotranslate fill path to
// land rows in localization.dynamic_translations. Round 10D Phase 2b.
//
// Returns nil when seam is nil so callers can defensively guard:
//
//	t := dynamicregistry.NewSeamTranslator(maybeSeam)
//	if t == nil { ... use NoopTranslator ... }
//
// Most production wirings call this unconditionally because the seam
// itself is always available; the back-compat nil case is for tests
// + lazy-init paths.
func NewSeamTranslator(seam *localization.Seam) *SeamTranslator {
	if seam == nil {
		return nil
	}
	return &SeamTranslator{seam: seam}
}

// Translate implements Translator.
//
// Builds a SourceRef from the (resourceType=namespace, resourceID,
// sourceVersion, sourceText) tuple and calls seam.Translate which
// handles cache/override probe + provider call + guard + persist.
// The return value (translated string) is intentionally discarded —
// the seam's persister already wrote the row, so the next request via
// the dynamicregistry DB-probe path will surface it.
//
// SeamTranslator.Translate is the goroutine-safe entry point the
// dynamicregistry calls; the seam itself is goroutine-safe by design
// (its protocols document this contract).
func (t *SeamTranslator) Translate(ctx context.Context, resourceType, resourceID, sourceVersion, sourceText, targetLocale string) {
	if t == nil || t.seam == nil {
		return
	}
	ref := localization.SourceRef{
		Namespace:     resourceType,
		SourceID:      resourceID,
		SourceVersion: sourceVersion,
		SourceText:    sourceText,
	}
	// seam.Translate returns the resolved string; we discard it
	// because the dynamicregistry already returned seed English to
	// the original caller. The side effect we care about is the
	// persister write inside the seam.
	_ = t.seam.Translate(ctx, ref, targetLocale)
}
