package llmroute

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type messageSink struct {
	mu   sync.Mutex
	msgs []string
}

func (m *messageSink) Enabled(context.Context, slog.Level) bool { return true }
func (m *messageSink) Handle(_ context.Context, r slog.Record) error {
	m.mu.Lock()
	m.msgs = append(m.msgs, r.Message)
	m.mu.Unlock()
	return nil
}
func (m *messageSink) WithAttrs([]slog.Attr) slog.Handler { return m }
func (m *messageSink) WithGroup(string) slog.Handler      { return m }

func (m *messageSink) usageLines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, msg := range m.msgs {
		if strings.HasPrefix(msg, "LLM_USAGE ") {
			out = append(out, msg)
		}
	}
	return out
}

func captureSlog(t *testing.T) *messageSink {
	t.Helper()
	sink := &messageSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return sink
}

func useService(t *testing.T, name string) {
	t.Helper()
	defaultMu.Lock()
	saved := defaultSvc
	defaultSvc = name
	defaultMu.Unlock()
	t.Cleanup(func() {
		defaultMu.Lock()
		defaultSvc = saved
		defaultMu.Unlock()
	})
}

func useRecorder(t *testing.T, rec *Recorder) {
	t.Helper()
	recorderMu.Lock()
	saved := recorder
	recorder = rec
	recorderMu.Unlock()
	t.Cleanup(func() {
		recorderMu.Lock()
		recorder = saved
		recorderMu.Unlock()
	})
}

func TestUsageLineIsTheSharedContract(t *testing.T) {
	got := UsageLine("kielo-cms", Sample{
		Task: "scene_practice_pack", Family: "scene_pack", Model: "claude-haiku-5-5", Provider: "anthropic",
		Requested: "claude-haiku-5-5", Variant: VariantCandidate, InputTokens: 120, OutputTokens: 45, ThinkingTokens: 7,
		USD: 0.00123456, Latency: 842900 * time.Microsecond, Outcome: OutcomeOK,
	})
	want := "LLM_USAGE task=scene_practice_pack service=kielo-cms family=scene_pack provider=anthropic model=claude-haiku-5-5 " +
		"requested=claude-haiku-5-5 variant=candidate in=120 out=45 thinking=7 usd=0.001235 latency_ms=842 outcome=ok fallback=0"
	if got != want {
		t.Fatalf("line =\n%s\nwant\n%s", got, want)
	}
}

func TestUsageLineFillsDefaultsAndNamesFallbacksAndErrors(t *testing.T) {
	got := UsageLine("svc", Sample{Family: "exercise_judge", Model: "gemini-3.8-flash", USD: 0.5})
	want := "LLM_USAGE task=exercise_judge service=svc family=exercise_judge provider=google model=gemini-3.8-flash " +
		"requested=gemini-3.8-flash variant=route in=0 out=0 thinking=0 usd=0.500000 latency_ms=0 outcome=ok fallback=0"
	if got != want {
		t.Fatalf("defaults:\n%s\nwant\n%s", got, want)
	}
	fell := UsageLine("svc", Sample{Family: "scene_pack", Model: "gemini-default", Requested: "claude-haiku-5-5", Fallback: true, Error: true})
	for _, part := range []string{"model=gemini-default requested=claude-haiku-5-5 variant=route", "outcome=error fallback=1"} {
		if !strings.Contains(fell, part) {
			t.Fatalf("fallback line %q lacks %q", fell, part)
		}
	}
	bare := UsageLine("", Sample{Model: "weird model", Outcome: "nonsense"})
	if !strings.HasPrefix(bare, "LLM_USAGE task=- service=- family=- provider=- model=weird_model requested=weird_model ") ||
		!strings.HasSuffix(bare, "outcome=ok fallback=0") {
		t.Fatalf("unknowns line = %q", bare)
	}
	if line := UsageLine("s", Sample{Family: "f", Model: "m", Outcome: OutcomeInvalidOutput}); !strings.HasSuffix(line, "outcome=invalid_output fallback=0") {
		t.Fatalf("invalid_output line = %q", line)
	}
	if line := UsageLine("s", Sample{Family: "f", Model: "m", USD: 0.00001}); !strings.Contains(line, "usd=0.000010 ") {
		t.Fatalf("a tiny usd must stay fixed-point: %q", line)
	}
}

func TestUsageLineKeepsWhatLogConsumersParse(t *testing.T) {
	line := UsageLine("svc", Sample{Family: "f", Model: "gemini-3.8-flash", InputTokens: 3, OutputTokens: 4, ThinkingTokens: 5, USD: 0.25})
	if !strings.HasPrefix(line, "LLM_USAGE task=") {
		t.Fatalf("the llm_calls metric filter needs the prefix: %q", line)
	}
	tally := regexp.MustCompile(`LLM_USAGE .*?in=(\d+) out=(\d+) thinking=(\d+) usd=([\d.]+)`).FindStringSubmatch(line)
	if len(tally) != 5 || tally[1] != "3" || tally[2] != "4" || tally[3] != "5" || tally[4] != "0.250000" {
		t.Fatalf("spend tally regex got %v from %q", tally, line)
	}
	if m := regexp.MustCompile(`task=([^ ]+)`).FindStringSubmatch(line); m[1] != "f" {
		t.Fatalf("task label = %v", m)
	}
	if m := regexp.MustCompile(`model=([^ ]+)`).FindStringSubmatch(line); m[1] != "gemini-3.8-flash" {
		t.Fatalf("model label = %v", m)
	}
}

func TestRecordLogsExactlyOneLineWithOrWithoutARecorder(t *testing.T) {
	sink := captureSlog(t)
	useService(t, "kielo-test")
	useRecorder(t, nil)
	Record(Sample{Family: "f", Model: "gemini-3.8-flash", InputTokens: 10, Outcome: OutcomeError})
	rec := NewRecorder("kielo-test", "http://unused", "")
	useRecorder(t, rec)
	Record(Sample{Family: "f", Model: "gemini-3.8-flash", InputTokens: 10})
	lines := sink.usageLines()
	if len(lines) != 2 {
		t.Fatalf("want one line per call, got %d: %v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "LLM_USAGE task=f service=kielo-test family=f provider=google model=gemini-3.8-flash ") ||
		!strings.HasSuffix(lines[0], "outcome=error fallback=0") {
		t.Fatalf("first line = %q", lines[0])
	}
	if rows := rec.Drain(); len(rows) != 1 || rows[0].Calls != 1 {
		t.Fatalf("the recorder must still count the call once: %+v", rows)
	}
}

type usagePosts struct {
	mu     sync.Mutex
	bodies []map[string]any
	keys   []string
}

func (u *usagePosts) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.bodies)
}

func (u *usagePosts) at(i int) (body map[string]any, key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bodies[i], u.keys[i]
}

func usageServer(t *testing.T, status int) (*httptest.Server, *usagePosts) {
	t.Helper()
	posts := &usagePosts{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		posts.mu.Lock()
		posts.bodies = append(posts.bodies, body)
		posts.keys = append(posts.keys, r.Header.Get("X-Internal-API-Key"))
		posts.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, posts
}

func TestFlushUsageSendsThePendingRollupSynchronously(t *testing.T) {
	captureSlog(t)
	srv, posts := usageServer(t, http.StatusOK)
	useRecorder(t, NewRecorder("svc", srv.URL, "secret"))
	Record(Sample{Family: "f", Model: "m", USD: 0.1, Latency: 12 * time.Millisecond})
	RecordOutcome("f", "m", true, 2)
	if err := FlushUsage(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if posts.count() != 1 {
		t.Fatalf("FlushUsage must have posted before returning, got %d posts", posts.count())
	}
	body, key := posts.at(0)
	rows, _ := body["rows"].([]any)
	row, _ := rows[0].(map[string]any)
	if len(rows) != 1 || row["family"] != "f" || row["model"] != "m" || row["calls"] != float64(1) || row["accepted"] != float64(2) {
		t.Fatalf("rows = %v", body)
	}
	if key != "secret" {
		t.Fatalf("api key header = %q", key)
	}
	if err := FlushUsage(context.Background()); err != nil || posts.count() != 1 {
		t.Fatalf("a second flush has nothing to send: err=%v posts=%d", err, posts.count())
	}
}

func TestFlushUsageIsANoOpUntilStartUsage(t *testing.T) {
	useRecorder(t, nil)
	if err := FlushUsage(context.Background()); err != nil {
		t.Fatalf("no recorder: %v", err)
	}
	useRecorder(t, NewRecorder("svc", "", ""))
	Record(Sample{Family: "f", Model: "m"})
	if err := FlushUsage(context.Background()); err != nil {
		t.Fatalf("disabled recorder: %v", err)
	}
}

func TestFlushUsageKeepsTheRowsWhenThePostFails(t *testing.T) {
	captureSlog(t)
	srv, posts := usageServer(t, http.StatusInternalServerError)
	rec := NewRecorder("svc", srv.URL, "")
	useRecorder(t, rec)
	Record(Sample{Family: "f", Model: "m", USD: 0.2})
	if err := FlushUsage(context.Background()); err == nil {
		t.Fatal("a 500 must come back as an error")
	}
	if posts.count() != 1 {
		t.Fatalf("posts = %d", posts.count())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := FlushUsage(ctx); err == nil {
		t.Fatal("a canceled context must stop the flush")
	}
	if rows := rec.Drain(); len(rows) != 1 || rows[0].Calls != 1 {
		t.Fatalf("the failed flushes must keep the rows: %+v", rows)
	}
}
