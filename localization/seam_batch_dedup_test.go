package localization

import (
	"context"
	"testing"
	"time"
)

// Intra-batch dedup on the provider fan-out. TranslateBatch built one
// provider item per ref unconditionally, so a batch that listed the same
// ref twice paid for it twice. Sibling of the Python seam's dedup in
// seam.py::_provider_batch_call; see the comment in providerBatchCall for
// why Go's unit is narrower (it sends namespace/source_id to the provider
// as disambiguating hints, so it must not collapse across them).
//
// The re-expansion tests are the load-bearing ones: a fan-out that
// mis-maps hands a learner a different learner's string.

// batchRecordingProvider echoes each item's text so a mis-mapped
// fan-out surfaces as a wrong value, not just a wrong call count.
type batchRecordingProvider struct {
	calls    int
	received [][]TranslationItem
}

func (p *batchRecordingProvider) ProviderID() string { return "batch-dedup-stub" }

func (p *batchRecordingProvider) TranslateBatch(
	_ context.Context,
	items []TranslationItem,
	opts TranslateOptions,
) ([]TranslationResult, error) {
	p.calls++
	snapshot := make([]TranslationItem, len(items))
	copy(snapshot, items)
	p.received = append(p.received, snapshot)
	out := make([]TranslationResult, len(items))
	for i, item := range items {
		out[i] = TranslationResult{
			Text:     opts.TargetLocale + ":" + item.Text,
			Provider: p.ProviderID(),
		}
	}
	return out, nil
}

func newDedupSeam(t *testing.T) (*Seam, *batchRecordingProvider) {
	t.Helper()
	provider := &batchRecordingProvider{}
	registry := NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.ProviderID()); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{now: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)}
	seam := NewSeam(
		registry,
		NewMemoryCache(clk.Now),
		MapOverrideStore{},
		NewCountingMetrics(),
		SeamConfig{FreshTTL: 0, StaleTTL: 0},
	)
	return seam, provider
}

func dedupRef(text, sourceID string) SourceRef {
	return SourceRef{
		Namespace:     "ui.string",
		SourceID:      sourceID,
		SourceVersion: SourceVersionFromText(text),
		SourceText:    text,
	}
}

func TestTranslateBatchCollapsesRepeatedRef(t *testing.T) {
	seam, provider := newDedupSeam(t)
	ref := dedupRef("Hyvä!", "praise.good")

	out := seam.TranslateBatch(context.Background(), []SourceRef{ref, ref, ref}, "vi")

	for i, got := range out {
		if got != "vi:Hyvä!" {
			t.Fatalf("position %d = %q, want %q", i, got, "vi:Hyvä!")
		}
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
	if n := len(provider.received[0]); n != 1 {
		t.Fatalf("provider received %d items for 3 identical refs, want 1", n)
	}
}

func TestTranslateBatchFanOutKeepsPositionsAligned(t *testing.T) {
	seam, provider := newDedupSeam(t)
	// Interleaved duplicates: a naive re-expansion shifts later results
	// onto the wrong ref.
	refs := []SourceRef{
		dedupRef("Alpha", "k.alpha"),
		dedupRef("Beta", "k.beta"),
		dedupRef("Alpha", "k.alpha"),
		dedupRef("Gamma", "k.gamma"),
		dedupRef("Beta", "k.beta"),
	}
	want := []string{"vi:Alpha", "vi:Beta", "vi:Alpha", "vi:Gamma", "vi:Beta"}

	out := seam.TranslateBatch(context.Background(), refs, "vi")

	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("position %d = %q, want %q", i, out[i], want[i])
		}
	}
	if n := len(provider.received[0]); n != 3 {
		t.Fatalf("provider received %d items, want 3 deduped", n)
	}
	for i, wantText := range []string{"Alpha", "Beta", "Gamma"} {
		if got := provider.received[0][i].Text; got != wantText {
			t.Fatalf("deduped item %d = %q, want %q (first-occurrence order)", i, got, wantText)
		}
	}
}

func TestTranslateBatchDoesNotCollapseDistinctSourceIDs(t *testing.T) {
	// namespace+source_id reach the provider as prompt hints so two
	// occurrences of one ambiguous string CAN translate differently.
	// Collapsing across them would silently discard that.
	seam, provider := newDedupSeam(t)
	refs := []SourceRef{
		dedupRef("Home", "nav.home"),
		dedupRef("Home", "noun.home"),
	}

	out := seam.TranslateBatch(context.Background(), refs, "vi")

	if out[0] != "vi:Home" || out[1] != "vi:Home" {
		t.Fatalf("out = %v", out)
	}
	if n := len(provider.received[0]); n != 2 {
		t.Fatalf("provider received %d items, want 2 (distinct hints)", n)
	}
}

func TestTranslateBatchDistinctTextsUnaffected(t *testing.T) {
	seam, provider := newDedupSeam(t)
	refs := []SourceRef{
		dedupRef("one", "k.1"),
		dedupRef("two", "k.2"),
		dedupRef("three", "k.3"),
	}

	out := seam.TranslateBatch(context.Background(), refs, "vi")

	for i, want := range []string{"vi:one", "vi:two", "vi:three"} {
		if out[i] != want {
			t.Fatalf("position %d = %q, want %q", i, out[i], want)
		}
	}
	if n := len(provider.received[0]); n != 3 {
		t.Fatalf("provider received %d items, want 3", n)
	}
}

// shortBatchProvider returns one result fewer than asked.
type shortBatchProvider struct{ batchRecordingProvider }

func (p *shortBatchProvider) TranslateBatch(
	ctx context.Context,
	items []TranslationItem,
	opts TranslateOptions,
) ([]TranslationResult, error) {
	out, err := p.batchRecordingProvider.TranslateBatch(ctx, items, opts)
	if err != nil {
		return nil, err
	}
	return out[:len(out)-1], nil
}

func TestTranslateBatchLengthCheckUsesDedupedItemCount(t *testing.T) {
	// Pre-dedup the guard compared len(results) != len(remaining). With
	// dedup that is wrong in both directions: a correct provider looks
	// short, and a genuinely short response can look correct. Source
	// fallback for every ref is the contract on a provider bug.
	provider := &shortBatchProvider{}
	registry := NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		t.Fatal(err)
	}
	if err := registry.Route("en", "vi", provider.ProviderID()); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{now: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)}
	seam := NewSeam(
		registry,
		NewMemoryCache(clk.Now),
		MapOverrideStore{},
		NewCountingMetrics(),
		SeamConfig{FreshTTL: 0, StaleTTL: 0},
	)
	ref := dedupRef("Alpha", "k.alpha")

	out := seam.TranslateBatch(
		context.Background(),
		[]SourceRef{ref, ref, dedupRef("Beta", "k.beta")},
		"vi",
	)

	want := []string{"Alpha", "Alpha", "Beta"}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("position %d = %q, want source fallback %q", i, out[i], want[i])
		}
	}
}
