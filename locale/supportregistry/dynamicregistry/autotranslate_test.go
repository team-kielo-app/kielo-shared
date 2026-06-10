package dynamicregistry

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/team-kielo-app/kielo-shared/localization"
)

// Round 10D regression tests for the autotranslate-on-miss hook in
// dynamicregistry.Registry. Each test pins one observable behavior
// of the WithTranslator wiring + queueAutotranslate dedupe path.

// recordingTranslator captures each Translate call for assertions.
// Safe for concurrent calls — the dynamicregistry queues goroutines
// from Resolve so tests must be able to wait for + assert on calls.
type recordingTranslator struct {
	mu    sync.Mutex
	calls []translatorCall
	done  chan struct{}
}

type translatorCall struct {
	resourceType  string
	resourceID    string
	sourceVersion string
	sourceText    string
	targetLocale  string
}

func newRecordingTranslator() *recordingTranslator {
	return &recordingTranslator{done: make(chan struct{}, 4)}
}

func (r *recordingTranslator) Translate(_ context.Context, resourceType, resourceID, sourceVersion, sourceText, targetLocale string) {
	r.mu.Lock()
	r.calls = append(r.calls, translatorCall{
		resourceType:  resourceType,
		resourceID:    resourceID,
		sourceVersion: sourceVersion,
		sourceText:    sourceText,
		targetLocale:  targetLocale,
	})
	r.mu.Unlock()
	// Non-blocking signal so multiple concurrent calls don't deadlock
	// when the test only waits for the first.
	select {
	case r.done <- struct{}{}:
	default:
	}
}

func (r *recordingTranslator) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingTranslator) Calls() []translatorCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]translatorCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// waitForCalls blocks until n distinct Translate invocations have
// been recorded or the timeout expires. Returns true when the count
// reached n in time.
func (r *recordingTranslator) waitForCalls(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if r.Count() >= n {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// blockingTranslator simulates a slow LLM call so concurrent miss
// requests can pile up while the first goroutine is still in flight.
// Tests assert the dedupe map prevents N concurrent goroutines from
// firing N LLM calls.
type blockingTranslator struct {
	released chan struct{}
	calls    atomic.Int32
	started  atomic.Int32
}

func newBlockingTranslator() *blockingTranslator {
	return &blockingTranslator{released: make(chan struct{})}
}

func (b *blockingTranslator) Translate(_ context.Context, _, _, _, _, _ string) {
	b.started.Add(1)
	b.calls.Add(1)
	<-b.released // block until the test releases
}

func (b *blockingTranslator) Release() {
	close(b.released)
}

// ---------- T1: nil/Noop translator preserves pre-Round-10D behavior ----------

func TestRound10D_T1_NoopTranslatorIsDefault(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	r := buildRegistry(t, seed, probe, cache)
	// No WithTranslator → default NoopTranslator.
	probe.setMiss("ui.greeting", "", "vi")
	// We need the right source_version — let the Registry compute it
	// by calling Resolve and reading the resulting probe key.
	got := r.Resolve(context.Background(), "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got, "vi seed value should fall through")
	// No way to assert "no goroutine spawned" externally — the
	// observable behavior is "no panic + correct return + no
	// background side effect". Pre-Round-10D Resolve had no goroutine
	// path; the NoopTranslator short-circuit guarantees the same.
}

// ---------- T2: WithTranslator wires the hook on DB-miss ----------

func TestRound10D_T2_DBMissQueuesAutotranslate(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()

	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)
	// Force a miss on (ui.greeting, vi).
	probe.setMiss("ui.greeting", "", "vi")
	// Resolve returns seed English (since no override) — vi seed value.
	got := r.Resolve(context.Background(), "ui.greeting", "vi")
	require.Equal(t, "Xin chào", got, "seed fallback returns vi seed value")
	// Wait for the background goroutine to fire.
	require.True(t, rec.waitForCalls(1, time.Second), "translator should be called once on DB-miss")
	calls := rec.Calls()
	require.Len(t, calls, 1)
	c := calls[0]
	assert.Equal(t, "ui.string", c.resourceType, "default resource_type is ui.string")
	assert.Equal(t, "ui.greeting", c.resourceID)
	assert.Equal(t, "vi", c.targetLocale)
	assert.Equal(t, "Hello", c.sourceText, "source text is the seed English")
	assert.NotEmpty(t, c.sourceVersion, "source version should be sha256 prefix")
}

// ---------- T3: concurrent misses for same (key, locale) dedupe ----------

func TestRound10D_T3_ConcurrentMissesDedupeViaInflightMap(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	block := newBlockingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(block)(r)
	probe.setMiss("ui.greeting", "", "vi")

	// Fire 8 concurrent Resolves for the same (key, locale).
	var wg sync.WaitGroup
	const N = 8
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.Resolve(context.Background(), "ui.greeting", "vi")
		}()
	}
	wg.Wait()
	// Give the goroutines a beat to call into the blocking translator.
	time.Sleep(50 * time.Millisecond)
	// Only ONE Translate should be in flight despite N concurrent
	// Resolves; the inflight map dedupes the rest.
	started := block.started.Load()
	assert.LessOrEqual(t, started, int32(1), "expected at most 1 in-flight Translate (dedupe), got %d", started)
	block.Release()
	// Sleep enough for the blocking goroutine to return + cleanup.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), block.calls.Load(), "exactly 1 total Translate call expected")
}

// ---------- T4: distinct (key, locale) pairs do NOT dedupe each other ----------

func TestRound10D_T4_DistinctKeysDoNotDedupe(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)
	probe.setMiss("ui.greeting", "", "vi")
	probe.setMiss("ui.farewell", "", "vi")

	_ = r.Resolve(context.Background(), "ui.greeting", "vi")
	_ = r.Resolve(context.Background(), "ui.farewell", "vi")
	require.True(t, rec.waitForCalls(2, time.Second), "both distinct keys should queue translates")
	assert.Equal(t, 2, rec.Count())
}

// ---------- T5: DB hit (override exists) does NOT queue translate ----------

func TestRound10D_T5_DBHitDoesNotQueueTranslate(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)
	// Compute the source_version the Registry will derive from "Hello".
	sv := sourceVersion("Hello")
	probe.setHit("ui.greeting", sv, "vi", "ADMIN_OVERRIDE")

	got := r.Resolve(context.Background(), "ui.greeting", "vi")
	assert.Equal(t, "ADMIN_OVERRIDE", got, "override wins")
	// Give any spurious goroutine a chance to fire.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, rec.Count(), "DB hit must not queue translate")
}

// ---------- T6: DB error does NOT queue translate (avoid LLM spam on DB outage) ----------

func TestRound10D_T6_DBErrorDoesNotQueueTranslate(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)
	probe.setError("ui.greeting", sourceVersion("Hello"), "vi", assertedDBError)

	got := r.Resolve(context.Background(), "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got, "DB error falls through to seed")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, rec.Count(), "DB error must not queue translate")
}

// ---------- T7: empty target locale does NOT queue translate ----------

func TestRound10D_T7_EmptyLocaleDoesNotQueueTranslate(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)

	got := r.Resolve(context.Background(), "ui.greeting", "")
	assert.Equal(t, "Hello", got, "empty locale falls through to seed (en)")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, rec.Count(), "empty locale must not queue translate")
}

// ---------- T8: English target locale does NOT queue translate ----------

func TestRound10D_T8_EnglishTargetDoesNotQueueTranslate(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)

	got := r.Resolve(context.Background(), "ui.greeting", "en")
	assert.Equal(t, "Hello", got, "en target returns seed source text directly")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, rec.Count(), "en target must not queue translate (en IS the SoT)")
}

// ---------- T9: negative cache hit does NOT re-queue translate ----------

func TestRound10D_T9_NegativeCacheHitDoesNotRequeue(t *testing.T) {
	seed := buildSeed(t)
	probe := newStubProbe()
	cache := newStubCache()
	rec := newRecordingTranslator()
	r := buildRegistry(t, seed, probe, cache)
	WithTranslator(rec)(r)
	probe.setMiss("ui.greeting", "", "vi")

	// First Resolve: DB-miss → queues translate.
	_ = r.Resolve(context.Background(), "ui.greeting", "vi")
	require.True(t, rec.waitForCalls(1, time.Second), "first miss queues translate")
	// Second Resolve within missTTL: should hit the negative cache
	// and skip BOTH the DB probe AND the queueAutotranslate call.
	_ = r.Resolve(context.Background(), "ui.greeting", "vi")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, rec.Count(),
		"negative cache hit must NOT re-queue translate (would defeat dedupe)")
}

// ---------- helpers ----------

// sourceVersion uses the canonical localization helper so tests assert
// the exact same value the Registry derives internally.
func sourceVersion(text string) string {
	return localization.SourceVersionFromText(text)
}

var assertedDBError = assertedDBErrSentinel("simulated DB error")

type assertedDBErrSentinel string

func (e assertedDBErrSentinel) Error() string { return string(e) }
