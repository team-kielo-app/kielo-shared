package localization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// seamStubProvider returns canned translations and records every call.
// It's the simplest TranslateBatch impl that's still observable enough
// for the seam tests to pin who got hit. Distinct from registry_test's
// stubProvider so both test suites can coexist in this package.
type seamStubProvider struct {
	id           string
	translations map[string]string
	calls        atomic.Int32
	errOn        atomic.Bool
	// delay (nanos) lets tests force a slow provider so single-flight
	// has a window in which sibling callers can pile onto the in-flight
	// call. Without this, the in-memory stub returns synchronously and
	// the SF test sees one call run to completion before any sibling
	// even enters singleflight.Do.
	delayNanos atomic.Int64
}

func (s *seamStubProvider) ProviderID() string { return s.id }

func (s *seamStubProvider) TranslateBatch(_ context.Context, items []TranslationItem, opts TranslateOptions) ([]TranslationResult, error) {
	s.calls.Add(1)
	if d := time.Duration(s.delayNanos.Load()); d > 0 {
		time.Sleep(d)
	}
	if s.errOn.Load() {
		return nil, errors.New("stub provider error")
	}
	out := make([]TranslationResult, len(items))
	for i, item := range items {
		key := opts.TargetLocale + "|" + item.Text
		value, ok := s.translations[key]
		if !ok {
			value = item.Text
		}
		out[i] = TranslationResult{Text: value, Provider: s.id}
	}
	return out, nil
}

// seamHarness bundles every dependency the seam tests reach into. The
// struct return shape (vs a multi-return tuple) keeps test sites
// readable as the dependency count grows and side-steps the dogsled lint
// warning when individual tests only care about one or two of these.
type seamHarness struct {
	seam      *Seam
	provider  *seamStubProvider
	metrics   *CountingMetrics
	overrides MapOverrideStore
	clock     *fakeClock
}

func newSeamHarness(t *testing.T) seamHarness {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)}
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
	overrides := MapOverrideStore{}
	cache := NewMemoryCache(clk.Now)
	metrics := NewCountingMetrics()
	seam := NewSeam(registry, cache, overrides, metrics, SeamConfig{
		FreshTTL: 1 * time.Hour,
		StaleTTL: 24 * time.Hour,
	})
	return seamHarness{
		seam:      seam,
		provider:  provider,
		metrics:   metrics,
		overrides: overrides,
		clock:     clk,
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// === passthrough ===========================================================

func TestSeam_EnglishIsPassthrough(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics := h.seam, h.provider, h.metrics
	got := seam.Translate(context.Background(), SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}, "en")
	if got != "Order a coffee" {
		t.Fatalf("en passthrough returned %q", got)
	}
	if provider.calls.Load() != 0 {
		t.Fatalf("provider should not be called for en path; got %d calls", provider.calls.Load())
	}
	if metrics.Count("convo.scenario.title", "en", "english_passthrough") != 1 {
		t.Fatal("expected 1 english_passthrough counter")
	}
}

func TestSeam_EmptyTargetLocaleIsPassthrough(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider := h.seam, h.provider
	got := seam.Translate(context.Background(), SourceRef{
		Namespace:  "convo.scenario.title",
		SourceID:   "s1",
		SourceText: "Hello",
	}, "")
	if got != "Hello" {
		t.Fatalf("empty target returned %q", got)
	}
	if provider.calls.Load() != 0 {
		t.Fatal("provider should not be called for empty target")
	}
}

func TestSeam_EmptySourceTextReturnsEmpty(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider := h.seam, h.provider
	got := seam.Translate(context.Background(), SourceRef{
		Namespace:  "convo.scenario.title",
		SourceID:   "s1",
		SourceText: "",
	}, "vi")
	if got != "" {
		t.Fatalf("empty source returned %q", got)
	}
	if provider.calls.Load() != 0 {
		t.Fatal("provider should not be called for empty source")
	}
}

// === override ==============================================================

func TestSeam_OverrideWinsOverProvider(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics, overrides := h.seam, h.provider, h.metrics, h.overrides
	overrides["convo.scenario.title|s1|v1|vi"] = "Cốc cà phê admin-edited"

	got := seam.Translate(context.Background(), SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}, "vi")
	if got != "Cốc cà phê admin-edited" {
		t.Fatalf("override didn't win: got %q", got)
	}
	if provider.calls.Load() != 0 {
		t.Fatal("provider should not be called when override exists")
	}
	if metrics.Count("convo.scenario.title", "vi", "override") != 1 {
		t.Fatal("expected 1 override counter")
	}
}

func TestSeam_OverrideWithStaleVersionFallsThrough(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics, overrides := h.seam, h.provider, h.metrics, h.overrides
	// Admin override was authored against source_version=v1...
	overrides["convo.scenario.title|s1|v1|vi"] = "Cốc cà phê v1-era"

	// ...but the request carries v2 (canonical English was edited).
	// The seam must NOT serve the v1 override; it should fall through
	// to the provider so the user sees a translation that matches the
	// current English source.
	got := seam.Translate(context.Background(), SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v2",
		SourceText:    "Order a coffee",
	}, "vi")
	if got != "Gọi một ly cà phê" {
		t.Fatalf("expected provider value when override version is stale, got %q", got)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("provider should be called when override version is stale")
	}
	if metrics.Count("convo.scenario.title", "vi", "override") != 0 {
		t.Fatal("override counter should NOT increment on stale version")
	}
}

// === cache hit / miss / SWR ==============================================

func TestSeam_FirstCallMissesThenCacheHits(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics := h.seam, h.provider, h.metrics
	ref := SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}

	first := seam.Translate(context.Background(), ref, "vi")
	if first != "Gọi một ly cà phê" {
		t.Fatalf("first call returned %q", first)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider should be called once; got %d", provider.calls.Load())
	}

	second := seam.Translate(context.Background(), ref, "vi")
	if second != "Gọi một ly cà phê" {
		t.Fatalf("second call returned %q", second)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider should NOT be called on cache hit; got %d", provider.calls.Load())
	}
	if metrics.Count("convo.scenario.title", "vi", "provider_call") != 1 {
		t.Fatal("expected 1 provider_call counter")
	}
	if metrics.Count("convo.scenario.title", "vi", "cache_hit") != 1 {
		t.Fatal("expected 1 cache_hit counter")
	}
}

func TestSeam_StaleWhileRevalidate(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics, clk := h.seam, h.provider, h.metrics, h.clock
	ref := SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}

	first := seam.Translate(context.Background(), ref, "vi")
	if first != "Gọi một ly cà phê" {
		t.Fatalf("first call returned %q", first)
	}

	// Advance past freshTTL (1h) but within staleTTL window.
	clk.Advance(2 * time.Hour)
	got := seam.Translate(context.Background(), ref, "vi")
	if got != "Gọi một ly cà phê" {
		t.Fatalf("SWR should serve stale value; got %q", got)
	}
	if metrics.Count("convo.scenario.title", "vi", "cache_swr") != 1 {
		t.Fatal("expected 1 cache_swr counter")
	}

	// Background refresh is async; give it a moment then assert it ran.
	time.Sleep(50 * time.Millisecond)
	if provider.calls.Load() < 2 {
		t.Fatalf("SWR background refresh did not run; provider calls=%d", provider.calls.Load())
	}
}

func TestSeam_CacheBustOnSourceVersionChange(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider := h.seam, h.provider
	v1 := SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}
	_ = seam.Translate(context.Background(), v1, "vi")
	if provider.calls.Load() != 1 {
		t.Fatal("v1 should trigger 1 provider call")
	}

	v2 := v1
	v2.SourceVersion = "v2" // author edited the source; cache key changes
	_ = seam.Translate(context.Background(), v2, "vi")
	if provider.calls.Load() != 2 {
		t.Fatalf("v2 should trigger a new provider call; got total %d", provider.calls.Load())
	}
}

// === single-flight =========================================================

func TestSeam_SingleFlightCoalescesParallelMisses(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics := h.seam, h.provider, h.metrics
	// Force the provider slow so sibling goroutines reliably enter
	// singleflight.Do before the first call finishes. 100ms is far
	// longer than the goroutine launch cost yet short enough to keep
	// the test fast.
	provider.delayNanos.Store(int64(100 * time.Millisecond))

	ref := SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}

	const goroutines = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			seam.Translate(context.Background(), ref, "vi")
		}()
	}
	close(start)
	wg.Wait()

	if got := provider.calls.Load(); got > 5 {
		t.Fatalf("single-flight failed to coalesce: provider got %d calls", got)
	}
	if metrics.Count("convo.scenario.title", "vi", "cache_miss_share") == 0 {
		t.Fatal("expected at least one cache_miss_share counter")
	}
}

// === provider error fallback ==============================================

func TestSeam_ProviderErrorFallsBackToSource(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider, metrics := h.seam, h.provider, h.metrics
	provider.errOn.Store(true)

	got := seam.Translate(context.Background(), SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}, "vi")
	if got != "Order a coffee" {
		t.Fatalf("provider error should fall back to source; got %q", got)
	}
	if metrics.Count("convo.scenario.title", "vi", "provider_error") == 0 {
		t.Fatal("expected at least one provider_error counter")
	}
}

func TestSeam_UnknownLocaleNoRouteFallsBackToSource(t *testing.T) {
	h := newSeamHarness(t)
	seam, metrics := h.seam, h.metrics
	got := seam.Translate(context.Background(), SourceRef{
		Namespace:     "convo.scenario.title",
		SourceID:      "s1",
		SourceVersion: "v1",
		SourceText:    "Order a coffee",
	}, "zz") // not registered
	if got != "Order a coffee" {
		t.Fatalf("unknown locale should fall back to source; got %q", got)
	}
	if metrics.Count("convo.scenario.title", "zz", "provider_error") == 0 {
		t.Fatal("expected at least one provider_error counter")
	}
}

// === SourceVersionFromText ===============================================

func TestSourceVersionFromText_Stable(t *testing.T) {
	a := SourceVersionFromText("Order a coffee")
	b := SourceVersionFromText("Order a coffee")
	if a != b {
		t.Fatalf("hash unstable: %q vs %q", a, b)
	}
	c := SourceVersionFromText("Order a tea")
	if a == c {
		t.Fatal("hash collides on different inputs")
	}
}

func TestSourceVersionFromText_OrderSensitive(t *testing.T) {
	a := SourceVersionFromText("Order a coffee", "2026-05-15T12:00:00Z")
	b := SourceVersionFromText("2026-05-15T12:00:00Z", "Order a coffee")
	if a == b {
		t.Fatal("multi-arg hash should be order-sensitive")
	}
}

// === batch ===============================================================

func TestSeam_TranslateBatch(t *testing.T) {
	h := newSeamHarness(t)
	seam, provider := h.seam, h.provider
	refs := []SourceRef{
		{Namespace: "convo.scenario.title", SourceID: "s1", SourceVersion: "v1", SourceText: "Order a coffee"},
		{Namespace: "convo.scenario.title", SourceID: "s2", SourceVersion: "v1", SourceText: "Hello"},
	}
	got := seam.TranslateBatch(context.Background(), refs, "vi")
	if len(got) != 2 {
		t.Fatalf("batch len mismatch: %d", len(got))
	}
	if got[0] != "Gọi một ly cà phê" || got[1] != "Xin chào" {
		t.Fatalf("batch results: %v", got)
	}
	if provider.calls.Load() != 2 {
		t.Fatalf("expected 2 provider calls for 2 unique refs; got %d", provider.calls.Load())
	}
}
