package localization

import (
	"context"
	"testing"
)

// A background fill is spawned with context.WithoutCancel, which drops
// cancellation but keeps every value — so before DetachBudget the async
// seam work incremented the counter belonging to the request that
// spawned it. Whether those increments landed depended on whether the
// goroutine beat the response flush, which made convo's GET /scenarios
// report refs=0 cold and refs=3 warm for byte-identical requests.
func TestDetachBudgetKeepsBackgroundWorkOffTheRequestCounter(t *testing.T) {
	reqCtx := WithBudget(context.Background())

	bgCtx := DetachBudget(context.WithoutCancel(reqCtx))
	RecordBudget(bgCtx, BudgetKindRefResolved, 3)
	RecordBudget(bgCtx, BudgetKindOverrideLookup, 1)

	if got := BudgetSnapshotFromContext(reqCtx).RefsResolved; got != 0 {
		t.Errorf("background refs leaked onto the request counter: got %d, want 0", got)
	}
	if got := BudgetSnapshotFromContext(reqCtx).OverrideLookups; got != 0 {
		t.Errorf("background override lookups leaked onto the request counter: got %d, want 0", got)
	}
	if got := BudgetSnapshotFromContext(bgCtx).RefsResolved; got != 3 {
		t.Errorf("background counter should still measure its own work: got %d, want 3", got)
	}
}

// Without the detach the leak is real, not theoretical — this pins the
// behavior DetachBudget exists to prevent, so a future refactor that
// drops the call fails here rather than in a flaky e2e guard.
func TestWithoutCancelAloneLeaksOntoTheRequestCounter(t *testing.T) {
	reqCtx := WithBudget(context.Background())

	RecordBudget(context.WithoutCancel(reqCtx), BudgetKindRefResolved, 3)

	if got := BudgetSnapshotFromContext(reqCtx).RefsResolved; got != 3 {
		t.Fatalf("expected WithoutCancel to share the counter (got %d) — if this "+
			"now reports 0, context value semantics changed and DetachBudget "+
			"may be redundant", got)
	}
}

// WithBudget deliberately no-ops when a counter is already wired, so it
// cannot be used to isolate a background goroutine. That asymmetry is
// the reason DetachBudget exists as a separate entry point.
func TestWithBudgetDoesNotResetAnExistingCounter(t *testing.T) {
	ctx := WithBudget(context.Background())
	RecordBudget(ctx, BudgetKindRefResolved, 2)

	if got := BudgetSnapshotFromContext(WithBudget(ctx)).RefsResolved; got != 2 {
		t.Errorf("WithBudget reset a live counter: got %d, want 2", got)
	}
}
