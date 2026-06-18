// Package localization (TTTT-I): per-request localization budget +
// tracing. Counts the number of cache-miss override lookups, cache
// reads, and provider calls a single request issues, then surfaces
// the totals so observability dashboards + a hard-fail dev gate
// can catch N+1 regressions before they hit prod.
//
// Wire-up: Seam.Translate + Seam.TranslateBatch increment the per-
// kind counter on the ctx; an Echo middleware reads the counts after
// the handler returns and stamps them as response headers. Optional
// dev-mode hard fail via WithBudget(ctx, limits) returns an error
// when the limits are exceeded — the handler can then either log or
// fail the request loudly.

package localization

import (
	"context"
	"sync/atomic"
)

// BudgetKind enumerates the cost categories the seam tracks.
type BudgetKind int

const (
	// BudgetKindOverrideLookup counts override DB queries (post-TTTT-B:
	// 1 composite SELECT per batch call; pre-TTTT-B: 1 per ref).
	BudgetKindOverrideLookup BudgetKind = iota
	// BudgetKindCacheGet counts Redis GET/MGET round-trips.
	BudgetKindCacheGet
	// BudgetKindProviderCall counts LLM / opus-mt provider calls
	// (per Sweep TTTT-B: typically 1 per batch).
	BudgetKindProviderCall
	// BudgetKindRefResolved counts total refs resolved (regardless of
	// path). A single batch call resolves N refs but only issues
	// O(1) round-trips, so this metric is the most useful for
	// detecting "fan-out got worse" regressions.
	BudgetKindRefResolved
	budgetKindCount
)

// budgetCounters is the per-request mutable counter. Stored on ctx
// behind a private key; readers use BudgetSnapshot to read.
type budgetCounters struct {
	values [budgetKindCount]int64
}

func (b *budgetCounters) add(kind BudgetKind, n int) {
	if b == nil || kind >= budgetKindCount {
		return
	}
	atomic.AddInt64(&b.values[kind], int64(n))
}

func (b *budgetCounters) snapshot() BudgetSnapshot {
	if b == nil {
		return BudgetSnapshot{}
	}
	return BudgetSnapshot{
		OverrideLookups: int(atomic.LoadInt64(&b.values[BudgetKindOverrideLookup])),
		CacheGets:       int(atomic.LoadInt64(&b.values[BudgetKindCacheGet])),
		ProviderCalls:   int(atomic.LoadInt64(&b.values[BudgetKindProviderCall])),
		RefsResolved:    int(atomic.LoadInt64(&b.values[BudgetKindRefResolved])),
	}
}

// BudgetSnapshot is the read-side view of the per-request counters.
// Cheap to copy; safe to embed in response payloads / logs.
type BudgetSnapshot struct {
	OverrideLookups int `json:"override_lookups"`
	CacheGets       int `json:"cache_gets"`
	ProviderCalls   int `json:"provider_calls"`
	RefsResolved    int `json:"refs_resolved"`
}

type budgetCtxKey struct{}

// WithBudget attaches a per-request counter to ctx. Returns a new ctx;
// callers should propagate this to every downstream localization call.
//
// The intended pattern is: an Echo middleware calls WithBudget on
// every request, then reads BudgetFromContext after the handler returns
// and stamps the totals as X-Localization-* response headers (visible
// to mobile dev tools + observability scrapers).
func WithBudget(ctx context.Context) context.Context {
	if BudgetFromContext(ctx) != nil {
		return ctx // already wired; don't reset
	}
	return context.WithValue(ctx, budgetCtxKey{}, &budgetCounters{})
}

// BudgetFromContext returns the active counters, or nil if WithBudget
// was never called on this ctx (e.g. background jobs, internal tests).
func BudgetFromContext(ctx context.Context) *budgetCounters {
	if ctx == nil {
		return nil
	}
	bc, _ := ctx.Value(budgetCtxKey{}).(*budgetCounters)
	return bc
}

// BudgetSnapshotFromContext returns the current snapshot, or a zero
// snapshot if no budget is wired.
func BudgetSnapshotFromContext(ctx context.Context) BudgetSnapshot {
	bc := BudgetFromContext(ctx)
	if bc == nil {
		return BudgetSnapshot{}
	}
	return bc.snapshot()
}

// RecordBudget bumps the counter for `kind` by `n`. No-op when no
// budget is wired (background workers). The seam calls this internally
// from Translate / TranslateBatch / the batch phase helpers; external
// code shouldn't need to.
func RecordBudget(ctx context.Context, kind BudgetKind, n int) {
	bc := BudgetFromContext(ctx)
	if bc == nil {
		return
	}
	bc.add(kind, n)
}
