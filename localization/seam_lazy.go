package localization

import (
	"context"
	"strings"
	"time"

	safego "github.com/team-kielo-app/kielo-shared/observe/safego"
)

// lazyFillTimeout bounds one background provider batch started by
// TranslateBatchLazy. Generous: a cold page of 20 glosses is one LLM call.
const lazyFillTimeout = 60 * time.Second

// TranslateBatchLazy is TranslateBatch for list reads that must not wait on
// the provider. Overrides and cache hits (fresh or stale-while-revalidate)
// resolve exactly as in TranslateBatch. Cold misses return the source text
// immediately, and ONE background provider batch fills the cache and the
// persister for them, so the next read of the same page is a hit. Keys
// another batch is already translating are left to that batch.
//
// Returns the values in request order and the number of refs served as
// source text because their translation is still pending. Callers use the
// count to decide whether a client-side refetch is worth scheduling.
//
// Mirrors the Python `localize_reusable_fields_batch(lazy=True)`: the
// learning hub localizes every item gloss at read time, and on a cold
// support-language cache the synchronous path cost one provider round-trip
// per item (47 s for a 100-item page, measured 2026-09-02).
func (s *Seam) TranslateBatchLazy(ctx context.Context, refs []SourceRef, targetLocale string) (values []string, deferred int) {
	values, remaining := s.batchResolveCached(ctx, refs, targetLocale)
	if len(remaining) == 0 {
		return values, 0
	}
	target := strings.TrimSpace(strings.ToLower(targetLocale))
	for _, r := range remaining {
		values[r.idx] = r.ref.SourceText
		s.metrics.Record(ctx, r.ref.Namespace, target, "provider_deferred")
	}
	s.scheduleLazyFill(ctx, remaining, target, len(refs))
	return values, len(remaining)
}

// TranslateLazy is the single-ref form of TranslateBatchLazy. The bool is
// false when the returned value is the untranslated source and a fill is
// pending.
func (s *Seam) TranslateLazy(ctx context.Context, ref SourceRef, targetLocale string) (string, bool) {
	values, pending := s.TranslateBatchLazy(ctx, []SourceRef{ref}, targetLocale)
	return values[0], pending == 0
}

// scheduleLazyFill claims the residue keys this call owns and translates them
// in one detached provider batch. The result is published through the same
// in-flight registry TranslateBatch uses, so a synchronous batch that arrives
// while the fill runs waits for it instead of re-sending the page.
func (s *Seam) scheduleLazyFill(ctx context.Context, remaining []residueEntry, target string, width int) {
	owned, _ := s.claimBatchKeys(remaining)
	if len(owned) == 0 {
		return
	}
	RecordBudget(ctx, BudgetKindProviderCall, 1)
	bgCtx, cancel := context.WithTimeout(DetachBudget(context.WithoutCancel(ctx)), lazyFillTimeout)
	safego.Go("localization_seam_lazy_fill", func() {
		defer cancel()
		fill := make([]string, width)
		s.providerBatchCall(bgCtx, owned, target, fill)
		s.releaseBatchKeys(owned, fill)
	})
}
