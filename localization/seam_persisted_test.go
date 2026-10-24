package localization

import (
	"context"
	"testing"
	"time"
)

const persistedProse = "Practice reading short Finnish sentences every day"

type countingRows struct {
	rows    MapOverrideStore
	lookups int
	batches int
}

func (c *countingRows) Lookup(ctx context.Context, ns, id, ver, target string) (string, bool) {
	c.lookups++
	return c.rows.Lookup(ctx, ns, id, ver, target)
}

type countingBatchRows struct{ countingRows }

func (c *countingBatchRows) BatchLookup(ctx context.Context, refs []OverrideRef, target string) (map[string]string, error) {
	c.batches++
	out := map[string]string{}
	for _, r := range refs {
		if v, ok := c.rows.Lookup(ctx, r.Namespace, r.SourceID, r.SourceVersion, target); ok {
			out[OverrideBatchKey(r.Namespace, r.SourceID, r.SourceVersion)] = v
		}
	}
	return out, nil
}

type persistedHarness struct {
	seam      *Seam
	provider  *seamStubProvider
	metrics   *CountingMetrics
	persister *MapPersister
	clock     *fakeClock
	cache     *MemoryCache
}

func newPersistedHarness(t *testing.T, persisted PersistedStore, overrides OverrideStore, answers map[string]string) persistedHarness {
	t.Helper()
	provider := &seamStubProvider{id: "stub-vi", translations: answers}
	registry := NewRegistry()
	if err := registry.Register(provider.id, provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.id); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{now: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)}
	cache := NewMemoryCache(clk.Now)
	metrics := NewCountingMetrics()
	persister := &MapPersister{}
	seam := NewSeamWith(registry, cache, overrides, metrics, persister, nil, SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour})
	if persisted != nil {
		seam.WithPersisted(persisted)
	}
	return persistedHarness{seam: seam, provider: provider, metrics: metrics, persister: persister, clock: clk, cache: cache}
}

func pref(id, text string) SourceRef {
	return SourceRef{Namespace: "ns", SourceID: id, SourceVersion: "v1", SourceText: text}
}

func TestPersisted_RowServedWithoutProvider(t *testing.T) {
	h := newPersistedHarness(t, MapOverrideStore{"ns|a|v1|vi": "Xin chao"}, nil, nil)
	if got := h.seam.Translate(context.Background(), pref("a", "Hello"), "vi"); got != "Xin chao" {
		t.Fatalf("got %q", got)
	}
	if h.provider.calls.Load() != 0 || len(h.persister.Calls) != 0 {
		t.Fatal("provider or persister called")
	}
	if h.metrics.Count("ns", "vi", "persisted") != 1 {
		t.Fatal("expected persisted metric")
	}
	h.seam.Translate(context.Background(), pref("a", "Hello"), "vi")
	if h.metrics.Count("ns", "vi", "cache_hit") != 1 {
		t.Fatal("row should have refilled the cache")
	}
}

func TestPersisted_AbsentTierKeepsProviderPath(t *testing.T) {
	h := newPersistedHarness(t, nil, nil, map[string]string{"vi|Hello": "Xin chao"})
	if got := h.seam.Translate(context.Background(), pref("a", "Hello"), "vi"); got != "Xin chao" {
		t.Fatalf("got %q", got)
	}
	if h.provider.calls.Load() != 1 || len(h.persister.Calls) != 1 {
		t.Fatal("expected provider call and persist")
	}
}

func TestPersisted_IdenticalProseRowIgnored(t *testing.T) {
	h := newPersistedHarness(t, MapOverrideStore{"ns|a|v1|vi": persistedProse}, nil, map[string]string{"vi|" + persistedProse: "Luyen doc moi ngay"})
	if got := h.seam.Translate(context.Background(), pref("a", persistedProse), "vi"); got != "Luyen doc moi ngay" {
		t.Fatalf("got %q", got)
	}
	if h.provider.calls.Load() != 1 || len(h.persister.Calls) != 1 {
		t.Fatal("stand-in row must fall through to the provider and be rewritten")
	}
}

func TestPersisted_IdenticalShortRowServed(t *testing.T) {
	h := newPersistedHarness(t, MapOverrideStore{"ns|a|v1|vi": "Kielo"}, nil, nil)
	if got := h.seam.Translate(context.Background(), pref("a", "Kielo"), "vi"); got != "Kielo" || h.provider.calls.Load() != 0 {
		t.Fatalf("got %q calls %d", got, h.provider.calls.Load())
	}
}

func TestPersisted_OverrideBeatsPersisted(t *testing.T) {
	rows := &countingRows{rows: MapOverrideStore{"ns|a|v1|vi": "machine"}}
	h := newPersistedHarness(t, rows, MapOverrideStore{"ns|a|v1|vi": "admin"}, nil)
	if got := h.seam.Translate(context.Background(), pref("a", "Hello"), "vi"); got != "admin" {
		t.Fatalf("got %q", got)
	}
	if rows.lookups != 0 {
		t.Fatal("persisted store consulted despite override")
	}
}

func TestPersisted_SWRRefreshUsesRow(t *testing.T) {
	h := newPersistedHarness(t, MapOverrideStore{"ns|a|v1|vi": "row"}, nil, nil)
	ref := pref("a", "Hello")
	_ = h.cache.Set(context.Background(), h.seam.cacheKey(ref, "vi"), "old", 25*time.Hour)
	h.clock.Advance(2 * time.Hour)
	if got := h.seam.Translate(context.Background(), ref, "vi"); got != "old" {
		t.Fatalf("got %q", got)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e, ok := h.cache.Get(context.Background(), h.seam.cacheKey(ref, "vi")); ok && e.Value == "row" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e, _ := h.cache.Get(context.Background(), h.seam.cacheKey(ref, "vi")); e.Value != "row" {
		t.Fatalf("cache not refreshed from row: %q", e.Value)
	}
	if h.provider.calls.Load() != 0 {
		t.Fatal("provider called during SWR despite persisted row")
	}
}

func TestPersisted_BatchOneQueryThenProviderForRest(t *testing.T) {
	rows := &countingBatchRows{countingRows{rows: MapOverrideStore{"ns|a|v1|vi": "A-row", "ns|b|v1|vi": persistedProse}}}
	h := newPersistedHarness(t, rows, nil, map[string]string{"vi|Bye": "Tam biet", "vi|" + persistedProse: "Luyen doc"})
	out := h.seam.TranslateBatch(context.Background(), []SourceRef{pref("a", "Hello"), pref("b", persistedProse), pref("c", "Bye")}, "vi")
	want := []string{"A-row", "Luyen doc", "Tam biet"}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("out[%d]=%q want %q", i, out[i], want[i])
		}
	}
	if rows.batches != 1 || rows.lookups != 0 {
		t.Fatalf("batches=%d lookups=%d", rows.batches, rows.lookups)
	}
	if h.provider.calls.Load() != 1 || len(h.persister.Calls) != 2 {
		t.Fatalf("provider=%d persisted=%d", h.provider.calls.Load(), len(h.persister.Calls))
	}
	if h.metrics.Count("ns", "vi", "persisted") != 1 {
		t.Fatal("expected one persisted metric")
	}
}

func TestPersisted_BatchAllRowsSkipsProvider(t *testing.T) {
	rows := &countingRows{rows: MapOverrideStore{"ns|a|v1|vi": "A", "ns|b|v1|vi": "B"}}
	h := newPersistedHarness(t, rows, nil, nil)
	out := h.seam.TranslateBatch(context.Background(), []SourceRef{pref("a", "Hello"), pref("b", "Bye")}, "vi")
	if out[0] != "A" || out[1] != "B" || h.provider.calls.Load() != 0 || rows.lookups != 2 {
		t.Fatalf("out=%v calls=%d lookups=%d", out, h.provider.calls.Load(), rows.lookups)
	}
}

func TestPersisted_UnchangedProviderValueNotPersistedAgain(t *testing.T) {
	h := newPersistedHarness(t, MapOverrideStore{"ns|a|v1|vi": persistedProse}, nil, nil)
	if got := h.seam.Translate(context.Background(), pref("a", persistedProse), "vi"); got != persistedProse {
		t.Fatalf("got %q", got)
	}
	if h.provider.calls.Load() != 1 || len(h.persister.Calls) != 0 {
		t.Fatalf("provider=%d persists=%d", h.provider.calls.Load(), len(h.persister.Calls))
	}
}

func TestIsProseAndEcho(t *testing.T) {
	if IsProse("Kielo") || IsProse("Hello {{name}} you") || !IsProse(persistedProse) {
		t.Fatal("prose rule")
	}
	if !IsSourceEcho(" Hello ", "hello") || IsSourceEcho("", "") {
		t.Fatal("echo rule")
	}
}
