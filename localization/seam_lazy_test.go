package localization

import (
	"context"
	"testing"
	"time"
)

func waitForProviderCalls(t *testing.T, h seamHarness, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.provider.calls.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("provider calls = %d, want >= %d", h.provider.calls.Load(), want)
}

func waitForCacheHit(t *testing.T, h seamHarness, ref SourceRef, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		values, pending := h.seam.TranslateBatchLazy(context.Background(), []SourceRef{ref}, "vi")
		if pending == 0 && values[0] == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("translation for %q never landed in cache", ref.SourceText)
}

func TestTranslateBatchLazy_ColdMissServesSourceAndFillsOnce(t *testing.T) {
	h := newSeamHarness(t)
	refs := []SourceRef{
		{Namespace: "base_word", SourceID: "1.meaning", SourceVersion: "v1", SourceText: "Hello"},
		{Namespace: "base_word", SourceID: "2.meaning", SourceVersion: "v1", SourceText: "Order a coffee"},
	}

	values, pending := h.seam.TranslateBatchLazy(context.Background(), refs, "vi")

	if pending != 2 {
		t.Fatalf("pending = %d, want 2", pending)
	}
	if values[0] != "Hello" || values[1] != "Order a coffee" {
		t.Fatalf("cold read must serve source text, got %v", values)
	}
	waitForProviderCalls(t, h, 1)
	waitForCacheHit(t, h, refs[0], "Xin chào")
	values, pending = h.seam.TranslateBatchLazy(context.Background(), refs, "vi")
	if pending != 0 || values[0] != "Xin chào" || values[1] != "Gọi một ly cà phê" {
		t.Fatalf("second read should be a full cache hit, got %v pending=%d", values, pending)
	}
	if got := h.provider.calls.Load(); got != 1 {
		t.Fatalf("provider should have been called exactly once (one batch), got %d", got)
	}
}

func TestTranslateBatchLazy_OverrideAndEnglishNeverDeferred(t *testing.T) {
	h := newSeamHarness(t)
	h.overrides[OverrideBatchKey("scenario", "s1", "v1")+"|vi"] = "Ghi đè"
	refs := []SourceRef{
		{Namespace: "scenario", SourceID: "s1", SourceVersion: "v1", SourceText: "Overridden"},
		{Namespace: "scenario", SourceID: "s2", SourceVersion: "v1", SourceText: ""},
	}
	values, pending := h.seam.TranslateBatchLazy(context.Background(), refs, "vi")
	if pending != 0 {
		t.Fatalf("pending = %d, want 0", pending)
	}
	if values[0] != "Ghi đè" || values[1] != "" {
		t.Fatalf("unexpected values %v", values)
	}
	values, pending = h.seam.TranslateBatchLazy(context.Background(), refs[:1], "en")
	if pending != 0 || values[0] != "Overridden" {
		t.Fatalf("English target must pass through, got %v pending=%d", values, pending)
	}
	if h.provider.calls.Load() != 0 {
		t.Fatalf("provider must not be called for overrides or English")
	}
}

func TestTranslateBatchLazy_ProviderErrorLeavesSourceServed(t *testing.T) {
	h := newSeamHarness(t)
	h.provider.errOn.Store(true)
	ref := SourceRef{Namespace: "base_word", SourceID: "9.meaning", SourceVersion: "v1", SourceText: "Hello"}

	values, pending := h.seam.TranslateBatchLazy(context.Background(), []SourceRef{ref}, "vi")
	if pending != 1 || values[0] != "Hello" {
		t.Fatalf("got %v pending=%d", values, pending)
	}
	waitForProviderCalls(t, h, 1)
	h.provider.errOn.Store(false)
	// The failed fill must not poison the key: a later read still gets a fill.
	waitForCacheHit(t, h, ref, "Xin chào")
}

func TestTranslateLazy_SingleRef(t *testing.T) {
	h := newSeamHarness(t)
	ref := SourceRef{Namespace: "base_word", SourceID: "3.meaning", SourceVersion: "v1", SourceText: "Hello"}
	value, ready := h.seam.TranslateLazy(context.Background(), ref, "vi")
	if ready || value != "Hello" {
		t.Fatalf("cold single ref should serve source and report not ready, got %q ready=%v", value, ready)
	}
	waitForCacheHit(t, h, ref, "Xin chào")
	value, ready = h.seam.TranslateLazy(context.Background(), ref, "vi")
	if !ready || value != "Xin chào" {
		t.Fatalf("warm single ref got %q ready=%v", value, ready)
	}
}
