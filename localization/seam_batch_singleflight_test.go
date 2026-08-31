package localization

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The batch path claimed "per-ref single-flight via singleflight.Group" for a
// group that only ever wrapped Translate. In prod the app's 4s/12s/30s
// pending-refetches each re-sent the same cold discovery page to the bridge
// while the first call was still running. Two overlapping batches must cost
// ONE provider call, and the second must receive the first's answers.
func TestSeam_TranslateBatch_OverlappingBatchesShareOneProviderCall(t *testing.T) {
	h := newSeamHarness(t)
	h.provider.delayNanos.Store(int64(150 * time.Millisecond))

	refs := []SourceRef{
		{Namespace: "convo.scenario.description", SourceID: "s1", SourceVersion: "v1", SourceText: "Order a coffee"},
		{Namespace: "convo.scenario.description", SourceID: "s2", SourceVersion: "v1", SourceText: "Hello"},
	}

	var wg sync.WaitGroup
	results := make([][]string, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 1 {
				time.Sleep(20 * time.Millisecond) // arrive while the first batch is in flight
			}
			results[i] = h.seam.TranslateBatch(context.Background(), refs, "vi")
		}(i)
	}
	wg.Wait()

	if got := h.provider.calls.Load(); got != 1 {
		t.Fatalf("overlapping batches made %d provider calls, want 1", got)
	}
	for i, out := range results {
		if out[0] != "Gọi một ly cà phê" || out[1] != "Xin chào" {
			t.Fatalf("batch %d got %v — the waiter must receive the owner's translations", i, out)
		}
	}
	if shared := h.metrics.Count("convo.scenario.description", "vi", "cache_miss_share"); shared != 2 {
		t.Fatalf("expected 2 cache_miss_share records for the waiting batch, got %d", shared)
	}
}

// A waiter must never outlive its own budget: if the owning batch is slower
// than the waiter's ctx, the waiter falls back to source text and returns.
func TestSeam_TranslateBatch_WaiterHonoursItsOwnDeadline(t *testing.T) {
	h := newSeamHarness(t)
	h.provider.delayNanos.Store(int64(400 * time.Millisecond))
	refs := []SourceRef{{Namespace: "ns", SourceID: "s1", SourceVersion: "v1", SourceText: "Hello"}}

	go h.seam.TranslateBatch(context.Background(), refs, "vi")
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	out := h.seam.TranslateBatch(ctx, refs, "vi")
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("waiter blocked past its deadline")
	}
	if out[0] != "Hello" {
		t.Fatalf("timed-out waiter must fall back to source text, got %q", out[0])
	}
}

// Keys are released even when the provider fails, so a failed owner cannot
// wedge every later batch on the same keys.
func TestSeam_TranslateBatch_FailedOwnerReleasesKeys(t *testing.T) {
	h := newSeamHarness(t)
	refs := []SourceRef{{Namespace: "ns", SourceID: "s1", SourceVersion: "v1", SourceText: "Hello"}}

	h.provider.errOn.Store(true)
	_ = h.seam.TranslateBatch(context.Background(), refs, "vi")
	h.provider.errOn.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := h.seam.TranslateBatch(ctx, refs, "vi")
	if out[0] != "Xin chào" {
		t.Fatalf("second batch after a failed owner got %q, want a fresh provider call", out[0])
	}
	if got := h.provider.calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2 (one failed, one retried)", got)
	}
}

// failingCache answers every read with a miss and refuses every write — the
// shape of a Redis outage. The handoff between an owning batch and a waiting
// batch must not depend on the cache at all.
type failingCache struct{}

func (failingCache) Get(context.Context, string) (CacheEntry, bool) { return CacheEntry{}, false }
func (failingCache) Set(context.Context, string, string, time.Duration) error {
	return errors.New("cache down")
}

func newSeamHarnessWithCache(t *testing.T, cache Cache) seamHarness {
	t.Helper()
	provider := &seamStubProvider{
		id:           "stub-vi",
		translations: map[string]string{"vi|Order a coffee": "Gọi một ly cà phê", "vi|Hello": "Xin chào"},
	}
	registry := NewRegistry()
	if err := registry.Register(provider.id, provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.id); err != nil {
		t.Fatal(err)
	}
	metrics := NewCountingMetrics()
	seam := NewSeam(registry, cache, MapOverrideStore{}, metrics, SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour})
	return seamHarness{seam: seam, provider: provider, metrics: metrics}
}

// The first implementation re-looked the key up after the owner had deleted
// it and fell back to the CACHE for the value. MemoryCache hid that: the
// owner's write made the waiter look correct. With NoopCache (a supported
// configuration) or a failed cache write the waiter returned the SOURCE text
// after a successful translation. The waiter must receive the owner's value
// through the in-flight entry it captured at claim time, never via the cache.
func TestSeam_TranslateBatch_WaiterGetsOwnersValueWithoutAnyCache(t *testing.T) {
	for name, cache := range map[string]Cache{"noop": NoopCache{}, "failing": failingCache{}} {
		t.Run(name, func(t *testing.T) {
			h := newSeamHarnessWithCache(t, cache)
			h.provider.delayNanos.Store(int64(150 * time.Millisecond))
			refs := []SourceRef{
				{Namespace: "ns", SourceID: "s1", SourceVersion: "v1", SourceText: "Order a coffee"},
				{Namespace: "ns", SourceID: "s2", SourceVersion: "v1", SourceText: "Hello"},
			}

			var wg sync.WaitGroup
			results := make([][]string, 2)
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					if i == 1 {
						time.Sleep(20 * time.Millisecond)
					}
					results[i] = h.seam.TranslateBatch(context.Background(), refs, "vi")
				}(i)
			}
			wg.Wait()

			if got := h.provider.calls.Load(); got != 1 {
				t.Fatalf("provider calls = %d, want 1", got)
			}
			for i, out := range results {
				if out[0] != "Gọi một ly cà phê" || out[1] != "Xin chào" {
					t.Fatalf("batch %d got %v — waiter fell back to source text without a cache", i, out)
				}
			}
		})
	}
}

// ABA guard: a waiter captured entry E1 for key K. The owner finishes and
// frees K; a THIRD batch claims K with a fresh entry E2 before the waiter
// runs. The waiter must still resolve from E1 (already closed with the
// owner's value), not block on or read E2.
func TestSeam_TranslateBatch_WaiterIsNotConfusedByALaterClaimOnTheSameKey(t *testing.T) {
	h := newSeamHarnessWithCache(t, NoopCache{})
	refs := []SourceRef{{Namespace: "ns", SourceID: "s1", SourceVersion: "v1", SourceText: "Hello"}}
	key := h.seam.cacheKey(refs[0], "vi")

	// Simulate: waiter claims while E1 is in flight.
	e1 := &batchInFlightEntry{done: make(chan struct{})}
	h.seam.batchInFlight.Store(key, e1)
	remaining := []residueEntry{{idx: 0, ref: refs[0], key: key}}
	owned, shared := h.seam.claimBatchKeys(remaining)
	if len(owned) != 0 || len(shared) != 1 || shared[0].entry != e1 {
		t.Fatalf("waiter must capture the exact in-flight entry")
	}

	// Owner finishes: frees K and publishes into E1. A later batch claims K anew.
	h.seam.batchInFlight.Delete(key)
	e1.value = "Xin chào"
	close(e1.done)
	e2 := &batchInFlightEntry{done: make(chan struct{})} // never completes
	h.seam.batchInFlight.Store(key, e2)

	out := make([]string, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	h.seam.awaitSharedBatchKeys(ctx, shared, "vi", out)
	if out[0] != "Xin chào" {
		t.Fatalf("waiter resolved %q; it must read E1, not the later E2", out[0])
	}
}
