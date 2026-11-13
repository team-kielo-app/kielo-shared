package localization

import (
	"context"
	"testing"
	"time"
)

// An outage must leave no trace: the learner is served the source text for
// that one request, and neither the cache nor dynamic_translations keeps it,
// so the next request after the provider is back gets the translation. A
// cached or persisted source text would pin English for the TTL (or for
// good) after a provider blip.

type emptyResultProvider struct{ calls int }

func (p *emptyResultProvider) ProviderID() string { return "empty" }

func (p *emptyResultProvider) TranslateBatch(context.Context, []TranslationItem, TranslateOptions) ([]TranslationResult, error) {
	p.calls++
	return nil, nil
}

type outageHarness struct {
	seam      *Seam
	provider  *seamStubProvider
	cache     *MemoryCache
	persister *lockedPersister
}

func newOutageHarness(t *testing.T) outageHarness {
	t.Helper()
	provider := &seamStubProvider{
		id: "stub-vi",
		translations: map[string]string{
			"vi|Order a coffee": "Gọi một ly cà phê",
			"vi|Hello":          "Xin chào",
		},
	}
	registry := NewRegistry()
	if err := registry.Register(provider.id, provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.id); err != nil {
		t.Fatal(err)
	}
	cache := NewMemoryCache(time.Now)
	persister := &lockedPersister{}
	seam := NewSeamWith(registry, cache, MapOverrideStore{}, NewCountingMetrics(), persister, NoopGuard{}, SeamConfig{
		FreshTTL: time.Hour,
		StaleTTL: 24 * time.Hour,
	})
	return outageHarness{seam: seam, provider: provider, cache: cache, persister: persister}
}

func (h outageHarness) persisted() int {
	h.persister.mu.Lock()
	defer h.persister.mu.Unlock()
	return len(h.persister.calls)
}

func (h outageHarness) assertNoTrace(t *testing.T, refs ...SourceRef) {
	t.Helper()
	for _, ref := range refs {
		if entry, ok := h.cache.Get(context.Background(), h.seam.cacheKey(ref, "vi")); ok {
			t.Fatalf("an outage cached %q for %s", entry.Value, ref.SourceID)
		}
	}
	if n := h.persisted(); n != 0 {
		t.Fatalf("an outage persisted %d rows", n)
	}
}

func TestSeamOutage_SingleIsServedSourceAndLeavesNoTrace(t *testing.T) {
	h := newOutageHarness(t)
	ref := SourceRef{Namespace: "convo.scenario.title", SourceID: "s1", SourceVersion: "v1", SourceText: "Order a coffee"}
	h.provider.errOn.Store(true)

	if got := h.seam.Translate(context.Background(), ref, "vi"); got != "Order a coffee" {
		t.Fatalf("got %q", got)
	}
	h.assertNoTrace(t, ref)

	h.provider.errOn.Store(false)
	if got := h.seam.Translate(context.Background(), ref, "vi"); got != "Gọi một ly cà phê" {
		t.Fatalf("after the provider came back got %q", got)
	}
	if entry, ok := h.cache.Get(context.Background(), h.seam.cacheKey(ref, "vi")); !ok || entry.Value != "Gọi một ly cà phê" {
		t.Fatalf("the real translation was not cached: %+v ok=%v", entry, ok)
	}
	if n := h.persisted(); n != 1 {
		t.Fatalf("the real translation was persisted %d times, want 1", n)
	}
}

func TestSeamOutage_BatchIsServedSourceAndLeavesNoTrace(t *testing.T) {
	h := newOutageHarness(t)
	refs := []SourceRef{
		{Namespace: "base_word", SourceID: "1.meaning", SourceVersion: "v1", SourceText: "Order a coffee"},
		{Namespace: "base_word", SourceID: "2.meaning", SourceVersion: "v1", SourceText: "Hello"},
	}
	h.provider.errOn.Store(true)

	got := h.seam.TranslateBatch(context.Background(), refs, "vi")
	if len(got) != 2 || got[0] != "Order a coffee" || got[1] != "Hello" {
		t.Fatalf("got %v", got)
	}
	h.assertNoTrace(t, refs...)

	h.provider.errOn.Store(false)
	got = h.seam.TranslateBatch(context.Background(), refs, "vi")
	if got[0] != "Gọi một ly cà phê" || got[1] != "Xin chào" {
		t.Fatalf("after the provider came back got %v", got)
	}
	if n := h.persisted(); n != 2 {
		t.Fatalf("the real translations were persisted %d times, want 2", n)
	}
}

// The translate provider answers (nil, nil) when its client is unavailable:
// no error, no results. That is an outage too.
func TestSeamOutage_AnEmptyAnswerLeavesNoTrace(t *testing.T) {
	provider := &emptyResultProvider{}
	registry := NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.ProviderID()); err != nil {
		t.Fatal(err)
	}
	cache := NewMemoryCache(time.Now)
	persister := &lockedPersister{}
	seam := NewSeamWith(registry, cache, MapOverrideStore{}, NewCountingMetrics(), persister, NoopGuard{}, SeamConfig{})
	h := outageHarness{seam: seam, cache: cache, persister: persister}
	one := SourceRef{Namespace: "n", SourceID: "a", SourceVersion: "v1", SourceText: "Hello"}
	two := SourceRef{Namespace: "n", SourceID: "b", SourceVersion: "v1", SourceText: "Order a coffee"}

	if got := seam.Translate(context.Background(), one, "vi"); got != "Hello" {
		t.Fatalf("got %q", got)
	}
	if got := seam.TranslateBatch(context.Background(), []SourceRef{one, two}, "vi"); got[0] != "Hello" || got[1] != "Order a coffee" {
		t.Fatalf("got %v", got)
	}
	if provider.calls != 2 {
		t.Fatalf("provider asked %d times, want 2 (the first failure must not be cached)", provider.calls)
	}
	h.assertNoTrace(t, one, two)
}

func TestSeamOutage_NoRouteLeavesNoTrace(t *testing.T) {
	h := newOutageHarness(t)
	ref := SourceRef{Namespace: "n", SourceID: "a", SourceVersion: "v1", SourceText: "Hello"}
	if got := h.seam.Translate(context.Background(), ref, "zz"); got != "Hello" {
		t.Fatalf("got %q", got)
	}
	if _, ok := h.cache.Get(context.Background(), h.seam.cacheKey(ref, "zz")); ok {
		t.Fatal("a locale with no provider cached the source text")
	}
	if n := h.persisted(); n != 0 {
		t.Fatalf("persisted %d rows", n)
	}
}

// The engine's /internal/translate-batch answers 200 with "" for an item its
// own model failed on. That item is an outage for one string: served as
// source and not kept, while the other items are.
type blankForProvider struct{ blank string }

func (p blankForProvider) ProviderID() string { return "blank-for" }

func (p blankForProvider) TranslateBatch(_ context.Context, items []TranslationItem, _ TranslateOptions) ([]TranslationResult, error) {
	out := make([]TranslationResult, len(items))
	for i, item := range items {
		if item.Text != p.blank {
			out[i] = TranslationResult{Text: "vi:" + item.Text, Provider: "blank-for"}
		}
	}
	return out, nil
}

func TestSeamOutage_AFailedItemInAnAnsweredBatchLeavesNoTrace(t *testing.T) {
	provider := blankForProvider{blank: "Hello"}
	registry := NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.ProviderID()); err != nil {
		t.Fatal(err)
	}
	cache := NewMemoryCache(time.Now)
	persister := &lockedPersister{}
	seam := NewSeamWith(registry, cache, MapOverrideStore{}, NewCountingMetrics(), persister, NoopGuard{}, SeamConfig{})
	failed := SourceRef{Namespace: "n", SourceID: "a", SourceVersion: "v1", SourceText: "Hello"}
	fine := SourceRef{Namespace: "n", SourceID: "b", SourceVersion: "v1", SourceText: "Order a coffee"}

	got := seam.TranslateBatch(context.Background(), []SourceRef{failed, fine}, "vi")
	if got[0] != "Hello" || got[1] != "vi:Order a coffee" {
		t.Fatalf("got %v", got)
	}
	if entry, ok := cache.Get(context.Background(), seam.cacheKey(failed, "vi")); ok {
		t.Fatalf("the failed item was cached as %q", entry.Value)
	}
	if _, ok := cache.Get(context.Background(), seam.cacheKey(fine, "vi")); !ok {
		t.Fatal("the translated neighbour was not cached")
	}
	persister.mu.Lock()
	defer persister.mu.Unlock()
	if len(persister.calls) != 1 || persister.calls[0].SourceID != "b" {
		t.Fatalf("persisted %+v, want only the translated neighbour", persister.calls)
	}

	if single := seam.Translate(context.Background(), failed, "vi"); single != "Hello" {
		t.Fatalf("single got %q", single)
	}
	if _, ok := cache.Get(context.Background(), seam.cacheKey(failed, "vi")); ok {
		t.Fatal("the failed item was cached by the single path")
	}
}
