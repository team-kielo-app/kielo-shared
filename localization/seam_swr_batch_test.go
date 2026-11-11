package localization

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A batch read refreshes its stale values with ONE provider call. It used to
// start one refresh per key: a page of 20 scene descriptions went out as 20
// single-text calls inside 60 ms, the engine instance takes 10 at once, and
// Cloud Run started two more instances for a refresh nobody waits on (prod
// 2026-11-09..11, about 20 times a day).

type swrProvider struct {
	mu      sync.Mutex
	batches [][]string
	fail    atomic.Bool
	hold    chan struct{}
}

func (p *swrProvider) ProviderID() string { return "swr-stub" }

func (p *swrProvider) TranslateBatch(
	_ context.Context, items []TranslationItem, opts TranslateOptions,
) ([]TranslationResult, error) {
	texts := make([]string, len(items))
	for i, item := range items {
		texts[i] = item.Text
	}
	p.mu.Lock()
	p.batches = append(p.batches, texts)
	round := len(p.batches)
	hold := p.hold
	p.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if p.fail.Load() {
		return nil, errors.New("provider down")
	}
	out := make([]TranslationResult, len(items))
	for i, item := range items {
		out[i] = TranslationResult{
			Text:     fmt.Sprintf("%s#%d:%s", opts.TargetLocale, round, item.Text),
			Provider: p.ProviderID(),
		}
	}
	return out, nil
}

func (p *swrProvider) sizes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	sizes := make([]int, len(p.batches))
	for i, batch := range p.batches {
		sizes[i] = len(batch)
	}
	return sizes
}

type lockedPersister struct {
	mu    sync.Mutex
	calls []PersistCall
}

func (p *lockedPersister) Persist(_ context.Context, ref SourceRef, target, text string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, PersistCall{
		Namespace: ref.Namespace, SourceID: ref.SourceID, SourceVersion: ref.SourceVersion,
		TargetLocale: target, TranslatedText: text,
	})
	return nil
}

func (p *lockedPersister) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

type swrHarness struct {
	seam      *Seam
	provider  *swrProvider
	persister *lockedPersister
	metrics   *CountingMetrics
	clock     *fakeClock
}

func newSWRHarness(t *testing.T, persisted PersistedStore, guard SuspiciousTranslationGuard) swrHarness {
	t.Helper()
	provider := &swrProvider{}
	registry := NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.ProviderID()); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	metrics := NewCountingMetrics()
	persister := &lockedPersister{}
	seam := NewSeamWith(registry, NewMemoryCache(clk.Now), MapOverrideStore{}, metrics, persister, guard,
		SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour})
	if persisted != nil {
		seam.WithPersisted(persisted)
	}
	return swrHarness{seam: seam, provider: provider, persister: persister, metrics: metrics, clock: clk}
}

func sceneRefs(n int) []SourceRef {
	refs := make([]SourceRef, n)
	for i := range refs {
		refs[i] = SourceRef{
			Namespace:     "scenario.description",
			SourceID:      fmt.Sprintf("scene-%02d", i),
			SourceVersion: "v1",
			SourceText:    fmt.Sprintf("Order coffee number %d at the counter", i),
		}
	}
	return refs
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func swrIdle(s *Seam) bool {
	idle := true
	s.swrInFlight.Range(func(_, _ any) bool {
		idle = false
		return false
	})
	return idle
}

func TestSWRBatch_StalePageIsRefreshedWithOneProviderCall(t *testing.T) {
	h := newSWRHarness(t, nil, nil)
	refs := sceneRefs(20)
	ctx := context.Background()

	first := h.seam.TranslateBatch(ctx, refs, "vi")
	h.clock.Advance(2 * time.Hour)
	stale := h.seam.TranslateBatch(ctx, refs, "vi")

	for i := range refs {
		if stale[i] != first[i] {
			t.Fatalf("ref %d: the stale read must serve the cached value, got %q want %q", i, stale[i], first[i])
		}
	}
	waitFor(t, "the refresh", func() bool { return len(h.provider.sizes()) == 2 && swrIdle(h.seam) })
	if got := h.provider.sizes(); got[0] != 20 || got[1] != 20 {
		t.Fatalf("provider batches = %v, want one call of 20 for the fill and one of 20 for the refresh", got)
	}
	if got := h.metrics.Count("scenario.description", "vi", "cache_swr"); got != 20 {
		t.Fatalf("cache_swr = %d, want 20", got)
	}
	if got := h.metrics.Count("scenario.description", "vi", "provider_call"); got != 20 {
		t.Fatalf("provider_call = %d, want the 20 of the first fill only", got)
	}

	fresh := h.seam.TranslateBatch(ctx, refs, "vi")
	for i, ref := range refs {
		if want := "vi#2:" + ref.SourceText; fresh[i] != want {
			t.Fatalf("ref %d after the refresh = %q, want %q", i, fresh[i], want)
		}
	}
	if got := h.provider.sizes(); len(got) != 2 {
		t.Fatalf("a read after the refresh must be served from the cache, provider batches = %v", got)
	}
	if got := h.persister.count(); got != 40 {
		t.Fatalf("persisted %d values, want 20 from the fill and 20 from the refresh", got)
	}
}

func TestSWRBatch_FreshAndMissingKeysAreNotInTheRefresh(t *testing.T) {
	h := newSWRHarness(t, nil, nil)
	refs := sceneRefs(6)
	ctx := context.Background()

	h.seam.TranslateBatch(ctx, refs[:3], "vi")
	h.clock.Advance(2 * time.Hour)
	h.seam.TranslateBatch(ctx, refs[3:5], "vi")
	h.seam.TranslateBatch(ctx, refs, "vi")

	waitFor(t, "the refresh", func() bool { return len(h.provider.sizes()) == 4 && swrIdle(h.seam) })
	sizes := h.provider.sizes()
	if sizes[0] != 3 || sizes[1] != 2 {
		t.Fatalf("fills = %v, want 3 then 2", sizes[:2])
	}
	// The third read sends its one miss inline and its three stale keys in
	// the background; which call the provider sees first is not ordered.
	missThenStale := sizes[2] == 1 && sizes[3] == 3
	staleThenMiss := sizes[2] == 3 && sizes[3] == 1
	if !missThenStale && !staleThenMiss {
		t.Fatalf("third read sent %v, want the 1 miss and the 3 stale keys as two calls", sizes[2:])
	}
}

func TestSWRBatch_KeysAlreadyBeingRefreshedAreNotSentAgain(t *testing.T) {
	h := newSWRHarness(t, nil, nil)
	refs := sceneRefs(8)
	ctx := context.Background()
	h.seam.TranslateBatch(ctx, refs, "vi")
	h.clock.Advance(2 * time.Hour)

	hold := make(chan struct{})
	h.provider.mu.Lock()
	h.provider.hold = hold
	h.provider.mu.Unlock()
	h.seam.TranslateBatch(ctx, refs, "vi")
	waitFor(t, "the refresh to reach the provider", func() bool { return len(h.provider.sizes()) == 2 })
	h.seam.TranslateBatch(ctx, refs, "vi")
	h.seam.TranslateBatch(ctx, refs[:4], "vi")
	close(hold)

	waitFor(t, "the refresh to finish", func() bool { return swrIdle(h.seam) })
	if got := h.provider.sizes(); len(got) != 2 || got[1] != 8 {
		t.Fatalf("provider batches = %v, want the fill and one refresh of 8", got)
	}
}

func TestSWRBatch_UsablePersistedRowsRefillTheCacheWithoutTheProvider(t *testing.T) {
	refs := sceneRefs(4)
	rows := &countingBatchRows{countingRows: countingRows{rows: MapOverrideStore{}}}
	h := newSWRHarness(t, rows, nil)
	ctx := context.Background()
	h.seam.TranslateBatch(ctx, refs, "vi")
	for _, ref := range refs[:3] {
		rows.rows[ref.Namespace+"|"+ref.SourceID+"|"+ref.SourceVersion+"|vi"] = "row:" + ref.SourceText
	}
	h.clock.Advance(2 * time.Hour)
	batchesBefore := rows.batches

	h.seam.TranslateBatch(ctx, refs, "vi")

	waitFor(t, "the refresh", func() bool { return len(h.provider.sizes()) == 2 && swrIdle(h.seam) })
	if got := h.provider.sizes(); got[1] != 1 {
		t.Fatalf("the refresh sent %d texts to the provider, want only the 1 without a row", got[1])
	}
	if rows.batches != batchesBefore+1 {
		t.Fatalf("persisted rows read in %d batches, want 1", rows.batches-batchesBefore)
	}
	after := h.seam.TranslateBatch(ctx, refs, "vi")
	for i, ref := range refs[:3] {
		if want := "row:" + ref.SourceText; after[i] != want {
			t.Fatalf("ref %d = %q, want the persisted row %q", i, after[i], want)
		}
	}
	if want := "vi#2:" + refs[3].SourceText; after[3] != want {
		t.Fatalf("ref 3 = %q, want the provider's refresh %q", after[3], want)
	}
}

func TestSWRBatch_RejectedAnswerDoesNotReplaceOrBlockItsSiblings(t *testing.T) {
	h := newSWRHarness(t, nil, &selectiveGuard{})
	refs := sceneRefs(3)
	ctx := context.Background()
	h.seam.TranslateBatch(ctx, refs, "vi")
	persistedBefore := h.persister.count()
	h.clock.Advance(2 * time.Hour)
	h.seam.guard = &selectiveGuard{rejectIfSrcContains: "number 1 "}

	h.seam.TranslateBatch(ctx, refs, "vi")

	waitFor(t, "the refresh", func() bool { return len(h.provider.sizes()) == 2 && swrIdle(h.seam) })
	if got := h.metrics.Count("scenario.description", "vi", "guard_rejected"); got != 1 {
		t.Fatalf("guard_rejected = %d, want 1", got)
	}
	if got := h.persister.count() - persistedBefore; got != 2 {
		t.Fatalf("the refresh persisted %d values, want the 2 that passed the guard", got)
	}
	after := h.seam.TranslateBatch(ctx, refs, "vi")
	if after[1] != refs[1].SourceText {
		t.Fatalf("the rejected ref = %q, want its source text", after[1])
	}
	if want := "vi#2:" + refs[0].SourceText; after[0] != want {
		t.Fatalf("a sibling = %q, want %q", after[0], want)
	}
}

func TestSWRBatch_FailedRefreshKeepsServingAndCanRunAgain(t *testing.T) {
	h := newSWRHarness(t, nil, nil)
	refs := sceneRefs(5)
	ctx := context.Background()
	first := h.seam.TranslateBatch(ctx, refs, "vi")
	h.clock.Advance(2 * time.Hour)
	h.provider.fail.Store(true)

	h.seam.TranslateBatch(ctx, refs, "vi")

	waitFor(t, "the failed refresh", func() bool { return len(h.provider.sizes()) == 2 && swrIdle(h.seam) })
	if got := h.metrics.Count("scenario.description", "vi", "provider_error"); got != 5 {
		t.Fatalf("provider_error = %d, want 5", got)
	}
	h.provider.fail.Store(false)
	again := h.seam.TranslateBatch(ctx, refs, "vi")
	for i := range refs {
		if again[i] != first[i] {
			t.Fatalf("ref %d after a failed refresh = %q, want the cached %q", i, again[i], first[i])
		}
	}
	waitFor(t, "the second refresh", func() bool { return len(h.provider.sizes()) == 3 && swrIdle(h.seam) })
	if got := h.provider.sizes(); got[2] != 5 {
		t.Fatalf("second refresh sent %d texts, want 5", got[2])
	}
}

func TestSWRBatch_SingleReadStillRefreshesItsOwnKey(t *testing.T) {
	h := newSWRHarness(t, nil, nil)
	ref := sceneRefs(1)[0]
	ctx := context.Background()
	h.seam.Translate(ctx, ref, "vi")
	h.clock.Advance(2 * time.Hour)

	if got := h.seam.Translate(ctx, ref, "vi"); got != "vi#1:"+ref.SourceText {
		t.Fatalf("stale single read = %q", got)
	}
	waitFor(t, "the refresh", func() bool { return len(h.provider.sizes()) == 2 && swrIdle(h.seam) })
}
