package localization

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// Round 10D regression tests for the seam's TranslationPersister +
// SuspiciousTranslationGuard wiring. Mirrors the 9-test contract from
// the Python sibling at
// kielo-shared/tests/test_localization_seam_round10a.py.
//
// Each test pins ONE invariant; combinations produce the 9 distinct
// observable behaviors of the Round 10D persister + guard wire.

// newRound10dHarness builds a seam wired with a MapPersister + the
// supplied guard. Tests assert on the persister's Calls slice + the
// returned string to verify the contract.
func newRound10dHarness(t *testing.T, guard SuspiciousTranslationGuard) (
	*Seam,
	*seamStubProvider,
	*MapPersister,
	*CountingMetrics,
) {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}
	provider := &seamStubProvider{
		id: "stub-vi",
		translations: map[string]string{
			"vi|Save":           "Lưu",
			"vi|Order a coffee": "Gọi một ly cà phê",
			"vi|Hello":          "Xin chào",
			"ja|Save":           "保存",
			"de|Save":           "Speichern",
		},
	}
	registry := NewRegistry()
	if err := registry.Register(provider.id, provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.id); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "ja", provider.id); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "de", provider.id); err != nil {
		t.Fatal(err)
	}
	persister := &MapPersister{}
	metrics := NewCountingMetrics()
	seam := NewSeamWith(
		registry,
		NewMemoryCache(clk.Now),
		MapOverrideStore{},
		metrics,
		persister,
		guard,
		SeamConfig{
			FreshTTL: 1 * time.Hour,
			StaleTTL: 24 * time.Hour,
		},
	)
	return seam, provider, persister, metrics
}

// T1: persister called with correct (namespace, source_id, source_version,
// target_locale, translated_text) tuple on single-item provider call.
func TestSeamRound10D_T1_PersisterCalledOnProviderCall(t *testing.T) {
	seam, provider, persister, _ := newRound10dHarness(t, NoopGuard{})
	ref := SourceRef{
		Namespace:     "ui.string",
		SourceID:      "ui.engine_string.Save",
		SourceVersion: "abc1234567890123",
		SourceText:    "Save",
	}
	got := seam.Translate(context.Background(), ref, "vi")
	if got != "Lưu" {
		t.Fatalf("expected provider output 'Lưu', got %q", got)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("expected 1 provider call, got %d", provider.calls.Load())
	}
	if len(persister.Calls) != 1 {
		t.Fatalf("expected 1 persister call, got %d", len(persister.Calls))
	}
	c := persister.Calls[0]
	if c.Namespace != "ui.string" {
		t.Errorf("namespace: want ui.string, got %s", c.Namespace)
	}
	if c.SourceID != "ui.engine_string.Save" {
		t.Errorf("source_id: want ui.engine_string.Save, got %s", c.SourceID)
	}
	if c.SourceVersion != "abc1234567890123" {
		t.Errorf("source_version: want abc1234567890123, got %s", c.SourceVersion)
	}
	if c.TargetLocale != "vi" {
		t.Errorf("target_locale: want vi, got %s", c.TargetLocale)
	}
	if c.TranslatedText != "Lưu" {
		t.Errorf("translated_text: want Lưu, got %s", c.TranslatedText)
	}
}

// T2: persister called N times on batch path (N = items, all distinct
// refs, all rendered). Mirrors Round 10A T2.
func TestSeamRound10D_T2_PersisterCalledNTimesOnBatch(t *testing.T) {
	seam, _, persister, _ := newRound10dHarness(t, NoopGuard{})
	refs := []SourceRef{
		{Namespace: "ui.string", SourceID: "ui.engine_string.Save", SourceVersion: "v1", SourceText: "Save"},
		{Namespace: "ui.string", SourceID: "ui.engine_string.Hello", SourceVersion: "v2", SourceText: "Hello"},
	}
	got := seam.TranslateBatch(context.Background(), refs, "vi")
	if len(got) != 2 || got[0] != "Lưu" || got[1] != "Xin chào" {
		t.Fatalf("batch returned %v", got)
	}
	if len(persister.Calls) != 2 {
		t.Fatalf("expected 2 persister calls, got %d", len(persister.Calls))
	}
	// Order is not asserted (batch may parallelize) — assert by set.
	got0 := persister.Calls[0].SourceID
	got1 := persister.Calls[1].SourceID
	if got0 != "ui.engine_string.Save" && got1 != "ui.engine_string.Save" {
		t.Errorf("expected Save in persister calls, got [%s,%s]", got0, got1)
	}
	if got0 != "ui.engine_string.Hello" && got1 != "ui.engine_string.Hello" {
		t.Errorf("expected Hello in persister calls, got [%s,%s]", got0, got1)
	}
}

// T3: guard rejection on single-item → source fallback, NO persist, NO
// cache write. Cache absence verified by issuing a second translate
// for the same ref and observing the provider hit AGAIN.
func TestSeamRound10D_T3_GuardRejectionSingleSkipsPersistAndCache(t *testing.T) {
	seam, provider, persister, _ := newRound10dHarness(t, AlwaysSuspiciousGuard{})
	ref := SourceRef{
		Namespace:     "ui.string",
		SourceID:      "ui.engine_string.Save",
		SourceVersion: "v1",
		SourceText:    "Save",
	}
	first := seam.Translate(context.Background(), ref, "vi")
	if first != "Save" {
		t.Fatalf("guard rejection should fall back to source 'Save', got %q", first)
	}
	if len(persister.Calls) != 0 {
		t.Fatalf("expected NO persister calls on guard rejection, got %d", len(persister.Calls))
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("expected 1 provider call so far, got %d", provider.calls.Load())
	}
	// Second translate for the same ref should hit provider AGAIN —
	// proves cache was NOT written.
	second := seam.Translate(context.Background(), ref, "vi")
	if second != "Save" {
		t.Fatalf("second call also rejected → source 'Save', got %q", second)
	}
	if provider.calls.Load() != 2 {
		t.Fatalf("expected 2 provider calls (no cache hit), got %d", provider.calls.Load())
	}
}

// T4: guard rejection on batch → per-item source fallback, siblings
// unaffected. One ref's source contains a junk marker (guard rule R6
// is the canonical rejection class); siblings translate normally.
func TestSeamRound10D_T4_GuardRejectionBatchSiblingsUnaffected(t *testing.T) {
	// Use a guard that rejects the second item only by checking source.
	seam, _, persister, _ := newRound10dHarness(t, &selectiveGuard{rejectIfSrcContains: "Hello"})
	refs := []SourceRef{
		{Namespace: "ui.string", SourceID: "k1", SourceVersion: "v1", SourceText: "Save"},
		{Namespace: "ui.string", SourceID: "k2", SourceVersion: "v2", SourceText: "Hello"},
	}
	got := seam.TranslateBatch(context.Background(), refs, "vi")
	if got[0] != "Lưu" {
		t.Errorf("sibling 1 should translate normally: got %q", got[0])
	}
	if got[1] != "Hello" {
		t.Errorf("sibling 2 should fall back to source 'Hello': got %q", got[1])
	}
	// Only sibling 1 should have been persisted.
	if len(persister.Calls) != 1 {
		t.Fatalf("expected 1 persister call (sibling 2 rejected), got %d", len(persister.Calls))
	}
	if persister.Calls[0].SourceID != "k1" {
		t.Errorf("expected persisted sibling 1, got %s", persister.Calls[0].SourceID)
	}
}

// T5: backward-compat — NewSeam (the legacy constructor that doesn't
// take persister/guard) defaults to NoopPersister + NoopGuard so
// existing callers preserve pre-Round-10D behavior.
func TestSeamRound10D_T5_LegacyConstructorPreservesBehaviour(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}
	provider := &seamStubProvider{
		id: "stub-vi",
		translations: map[string]string{
			"vi|Save": "Lưu",
		},
	}
	registry := NewRegistry()
	_ = registry.Register(provider.id, provider)
	_ = registry.Route("en", "vi", provider.id)
	seam := NewSeam(registry, NewMemoryCache(clk.Now), MapOverrideStore{}, NewCountingMetrics(),
		SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour})
	got := seam.Translate(context.Background(), SourceRef{
		Namespace: "ui.string", SourceID: "s1", SourceVersion: "v1", SourceText: "Save",
	}, "vi")
	if got != "Lưu" {
		t.Errorf("legacy seam should still translate via provider, got %q", got)
	}
	// No way to assert "noop persister was used" externally except
	// behaviorally — the call doesn't panic + returns the translation.
}

// T6: english passthrough never invokes persister or guard. The seam
// short-circuits before the provider path; persister/guard hooks must
// stay cold.
func TestSeamRound10D_T6_EnglishPassthroughSkipsPersisterAndGuard(t *testing.T) {
	g := &countingGuard{}
	seam, _, persister, _ := newRound10dHarness(t, g)
	got := seam.Translate(context.Background(), SourceRef{
		Namespace: "ui.string", SourceID: "s1", SourceVersion: "v1", SourceText: "Save",
	}, "en")
	if got != "Save" {
		t.Errorf("en passthrough should return source, got %q", got)
	}
	if len(persister.Calls) != 0 {
		t.Errorf("en passthrough should not call persister, got %d calls", len(persister.Calls))
	}
	if g.calls.Load() != 0 {
		t.Errorf("en passthrough should not call guard, got %d calls", g.calls.Load())
	}
}

// T7: override hit short-circuits before persister + guard. The seam
// resolves to the override value; the provider was never called, so the
// persister + guard hooks must stay cold.
func TestSeamRound10D_T7_OverrideHitSkipsPersisterAndGuard(t *testing.T) {
	seam, provider, persister, _ := newRound10dHarness(t, AlwaysSuspiciousGuard{})
	// Stash an override for (namespace, source_id, source_version, vi).
	// Reach through to the MapOverrideStore via the seam's overrides
	// field is unexported; we re-wire instead by constructing a fresh
	// harness with the override pre-populated.
	overrides := MapOverrideStore{}
	overrides["ui.string|s1|v1|vi"] = "ADMIN_OVERRIDE"
	clk := &fakeClock{now: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}
	seam = NewSeamWith(
		seam.registry,
		NewMemoryCache(clk.Now),
		overrides,
		NewCountingMetrics(),
		persister,
		AlwaysSuspiciousGuard{},
		SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour},
	)
	// Reset provider call counter — the previous seam ref'd this provider
	// but we threw away that seam.
	provider.calls.Store(0)
	got := seam.Translate(context.Background(), SourceRef{
		Namespace: "ui.string", SourceID: "s1", SourceVersion: "v1", SourceText: "Save",
	}, "vi")
	if got != "ADMIN_OVERRIDE" {
		t.Errorf("override should win, got %q", got)
	}
	if provider.calls.Load() != 0 {
		t.Errorf("override hit should not call provider, got %d calls", provider.calls.Load())
	}
	if len(persister.Calls) != 0 {
		t.Errorf("override hit should not call persister, got %d calls", len(persister.Calls))
	}
}

// T8: persister failures swallowed by the seam (translation still
// returns the LLM output; degraded but correct). Pins the "MUST swallow
// internal errors" contract from the protocol doc.
func TestSeamRound10D_T8_PersisterFailureSwallowed(t *testing.T) {
	// Build a custom seam wired with a failing persister.
	clk := &fakeClock{now: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}
	provider := &seamStubProvider{
		id: "stub-vi",
		translations: map[string]string{
			"vi|Save": "Lưu",
		},
	}
	registry := NewRegistry()
	_ = registry.Register(provider.id, provider)
	_ = registry.Route("en", "vi", provider.id)
	failingPersister := &failingPersister{}
	seam := NewSeamWith(
		registry,
		NewMemoryCache(clk.Now),
		MapOverrideStore{},
		NewCountingMetrics(),
		failingPersister,
		NoopGuard{},
		SeamConfig{FreshTTL: time.Hour, StaleTTL: 24 * time.Hour},
	)
	got := seam.Translate(context.Background(), SourceRef{
		Namespace: "ui.string", SourceID: "s1", SourceVersion: "v1", SourceText: "Save",
	}, "vi")
	if got != "Lưu" {
		t.Errorf("persister error must not break translation; got %q", got)
	}
	if failingPersister.calls.Load() != 1 {
		t.Errorf("persister should have been called once, got %d", failingPersister.calls.Load())
	}
}

// T9: guard_rejected metric records when guard rejects in batch path —
// a dedicated source tag (split from provider_error 2026-06-10) so
// dashboards separate rejection volume from provider failures.
func TestSeamRound10D_T9_GuardRejectionBatchRecordsGuardRejected(t *testing.T) {
	seam, _, _, metrics := newRound10dHarness(t, AlwaysSuspiciousGuard{})
	refs := []SourceRef{
		{Namespace: "ui.string", SourceID: "k1", SourceVersion: "v1", SourceText: "Save"},
		{Namespace: "ui.string", SourceID: "k2", SourceVersion: "v2", SourceText: "Hello"},
	}
	_ = seam.TranslateBatch(context.Background(), refs, "vi")
	got := metrics.Count("ui.string", "vi", "guard_rejected")
	if got != 2 {
		t.Errorf("expected 2 guard_rejected counters (one per rejected sibling), got %d", got)
	}
	if pe := metrics.Count("ui.string", "vi", "provider_error"); pe != 0 {
		t.Errorf("guard rejection must not count as provider_error, got %d", pe)
	}
}

// ---------- Test helpers (selectiveGuard / countingGuard / failingPersister) ----------

type selectiveGuard struct {
	rejectIfSrcContains string
}

func (g *selectiveGuard) IsSuspicious(src, _, _ string) bool {
	if g.rejectIfSrcContains == "" {
		return false
	}
	return strings.Contains(src, g.rejectIfSrcContains)
}

type countingGuard struct {
	calls atomicInt32
}

func (g *countingGuard) IsSuspicious(_, _, _ string) bool {
	g.calls.Add(1)
	return false
}

// atomicInt32 wraps sync/atomic to avoid the verbose `atomic.Int32`
// import dance in test helpers. (We don't have package atomic imported
// in this file otherwise.)
type atomicInt32 struct {
	mu sync.Mutex
	v  int32
}

func (a *atomicInt32) Add(delta int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.v += delta
}

func (a *atomicInt32) Load() int32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}

type failingPersister struct {
	calls atomicInt32
}

func (p *failingPersister) Persist(_ context.Context, _ SourceRef, _, _ string) error {
	p.calls.Add(1)
	return errPersisterStub
}

var errPersisterStub = errSentinel("persister stub error")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
