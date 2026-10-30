package llm

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/team-kielo-app/kielo-shared/llmroute"
)

type fakeProvider struct{ last Request }

func (f *fakeProvider) Generate(_ context.Context, req Request) (*Result, error) {
	f.last = req
	return &Result{RawText: "{}", InputTokens: 1000, OutputTokens: 500, ThinkingTokens: 500}, nil
}

func TestRoutingAppliesRouteAndBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/llm-models") {
			_, _ = w.Write([]byte(`{"items":[{"model":"gemini-3.8-flash","provider":"google"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"family":"unit_family","model":"gemini-3.8-flash","thinking_budget":0,"daily_budget_usd":0.001}]}`))
	}))
	defer srv.Close()
	llmroute.Configure("svc", srv.URL, "")
	inner := &fakeProvider{}
	p := WithRouting(inner)

	if _, err := p.Generate(context.Background(), Request{Prompt: "x", Model: "compiled", Family: "unit_family"}); err != nil {
		t.Fatal(err)
	}
	if inner.last.Model != "gemini-3.8-flash" || inner.last.ThinkingBudget == nil || *inner.last.ThinkingBudget != 0 {
		t.Fatalf("route not applied: %+v", inner.last)
	}
	_, err := p.Generate(context.Background(), Request{Prompt: "x", Model: "compiled", Family: "unit_family"})
	if !errors.Is(err, llmroute.ErrFamilyBudgetExceeded) {
		t.Fatalf("second call should hit the family budget, got %v", err)
	}
	if _, err := p.Generate(context.Background(), Request{Prompt: "x", Model: "keep"}); err != nil || inner.last.Model != "keep" {
		t.Fatalf("no family passes through: %v %+v", err, inner.last)
	}
}

func TestGeminiPayloadThinkingBudget(t *testing.T) {
	zero, def := 0, -1
	if _, ok := buildGeminiPayload(Request{Prompt: "x", ThinkingBudget: &zero})["generationConfig"]; !ok {
		t.Fatal("budget 0 must be sent")
	}
	if _, ok := buildGeminiPayload(Request{Prompt: "x", ThinkingBudget: &def})["generationConfig"]; ok {
		t.Fatal("budget -1 must leave the default")
	}
}

func canaryStore(routes string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/llm-models") {
			_, _ = w.Write([]byte(`{"items":[{"model":"gemini-3.8-flash","provider":"google"},{"model":"gemini-3.5-flash","provider":"google"},` +
				`{"model":"claude-haiku-5-5","provider":"anthropic"}]}`))
			return
		}
		_, _ = w.Write([]byte(routes))
	}))
}

func TestRoutingKeepsOneKeyOnOneModelWhileACanaryRuns(t *testing.T) {
	srv := canaryStore(`{"items":[{"family":"canary_family","model":"gemini-3.8-flash","thinking_budget":-1,` +
		`"candidate_model":"gemini-3.5-flash","candidate_thinking_budget":0,"candidate_share":50}]}`)
	defer srv.Close()
	llmroute.Configure("svc", srv.URL, "")
	t.Cleanup(func() { llmroute.Configure("", "", "") })
	inner := &fakeProvider{}
	p := WithRouting(inner)
	// crc32("canary_family:<key>") % 100 decides; the keys below sit on both sides of 50.
	seen := map[string]map[string]bool{}
	for i := 0; i < 40; i++ {
		key := "deck-" + string(rune('a'+i%20))
		if _, err := p.Generate(context.Background(), Request{Prompt: "x", Model: "compiled", Family: "canary_family", RouteKey: key}); err != nil {
			t.Fatal(err)
		}
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		seen[key][inner.last.Model] = true
	}
	models := map[string]bool{}
	for key, ms := range seen {
		if len(ms) != 1 {
			t.Fatalf("key %s saw several models: %v", key, ms)
		}
		for m := range ms {
			models[m] = true
		}
	}
	if !models["gemini-3.8-flash"] || !models["gemini-3.5-flash"] || len(models) != 2 {
		t.Fatalf("a 50%% canary over 20 keys should use both models, got %v", models)
	}
}

func TestRoutingRecordsAFallbackWhenTheRouteIsRefused(t *testing.T) {
	srv := canaryStore(`{"items":[{"family":"refused_family","model":"claude-haiku-5-5","thinking_budget":-1}]}`)
	defer srv.Close()
	llmroute.Configure("svc", srv.URL, "")
	t.Cleanup(func() { llmroute.Configure("", "", "") })
	posted := make(chan string, 8)
	usage := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		posted <- string(buf[:n])
	}))
	defer usage.Close()
	ctx, stop := context.WithCancel(context.Background())
	llmroute.StartUsage(ctx, usage.URL, "", 20*time.Millisecond)
	defer stop()

	inner := &fakeProvider{}
	if _, err := WithRouting(inner).Generate(context.Background(), Request{Prompt: "x", Model: "gemini-default", Family: "refused_family"}); err != nil {
		t.Fatal(err)
	}
	if inner.last.Model != "gemini-default" {
		t.Fatalf("a refused route must run the compiled default, got %q", inner.last.Model)
	}
	select {
	case body := <-posted:
		for _, want := range []string{`"model":"gemini-default"`, `"fallbacks":1`, `"errors":0`} {
			if !strings.Contains(body, want) {
				t.Fatalf("usage body %s lacks %s", body, want)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("usage rollup was not flushed")
	}
}

type failingProvider struct{}

func (failingProvider) Generate(context.Context, Request) (*Result, error) {
	return nil, &Error{Class: ErrorClassServerError, Err: errors.New("boom")}
}

func TestRoutingRecordsTheErrorOutcome(t *testing.T) {
	srv := canaryStore(`{"items":[{"family":"failing_family","model":"gemini-3.8-flash","thinking_budget":-1}]}`)
	defer srv.Close()
	llmroute.Configure("svc", srv.URL, "")
	t.Cleanup(func() { llmroute.Configure("", "", "") })
	posted := make(chan string, 8)
	usage := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		posted <- string(buf[:n])
	}))
	defer usage.Close()
	ctx, stop := context.WithCancel(context.Background())
	llmroute.StartUsage(ctx, usage.URL, "", 20*time.Millisecond)
	defer stop()

	if _, err := WithRouting(failingProvider{}).Generate(context.Background(), Request{Prompt: "x", Model: "d", Family: "failing_family"}); err == nil {
		t.Fatal("the provider error must come back")
	}
	select {
	case body := <-posted:
		if !strings.Contains(body, `"errors":1`) || !strings.Contains(body, `"fallbacks":0`) {
			t.Fatalf("usage body = %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("usage rollup was not flushed")
	}
}

type usageLineSink struct {
	mu    sync.Mutex
	lines []string
}

func (u *usageLineSink) Enabled(context.Context, slog.Level) bool { return true }
func (u *usageLineSink) Handle(_ context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "LLM_USAGE ") {
		u.mu.Lock()
		u.lines = append(u.lines, r.Message)
		u.mu.Unlock()
	}
	return nil
}
func (u *usageLineSink) WithAttrs([]slog.Attr) slog.Handler { return u }
func (u *usageLineSink) WithGroup(string) slog.Handler      { return u }

func captureUsageLines(t *testing.T) func() []string {
	t.Helper()
	sink := &usageLineSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []string {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return append([]string(nil), sink.lines...)
	}
}

func TestRoutingLogsOneUsageLineNamingTaskRequestedAndEffectiveModel(t *testing.T) {
	srv := canaryStore(`{"items":[{"family":"refused_family","model":"claude-haiku-5-5","thinking_budget":-1},` +
		`{"family":"served_family","model":"gemini-3.8-flash","thinking_budget":-1}]}`)
	defer srv.Close()
	llmroute.Configure("svc", srv.URL, "")
	t.Cleanup(func() { llmroute.Configure("", "", "") })
	lines := captureUsageLines(t)
	p := WithRouting(&fakeProvider{})
	if _, err := p.Generate(context.Background(), Request{Prompt: "x", Task: "scene_practice_pack", Model: "gemini-default", Family: "refused_family"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Generate(context.Background(), Request{Prompt: "x", Task: "judge", Model: "d", Family: "served_family"}); err != nil {
		t.Fatal(err)
	}
	if _, err := WithRouting(failingProvider{}).Generate(context.Background(), Request{Prompt: "x", Model: "gemini-default", Family: "served_family"}); err == nil {
		t.Fatal("the provider error must come back")
	}
	got := lines()
	if len(got) != 3 {
		t.Fatalf("want one line per call, got %d: %v", len(got), got)
	}
	for i, want := range []string{
		"LLM_USAGE task=scene_practice_pack service=svc family=refused_family provider=google model=gemini-default " +
			"requested=claude-haiku-5-5 variant=route in=1000 out=500 thinking=500 usd=",
		"LLM_USAGE task=judge service=svc family=served_family provider=google model=gemini-3.8-flash " +
			"requested=gemini-3.8-flash variant=route in=1000 out=500 thinking=500 usd=",
		"LLM_USAGE task=served_family service=svc family=served_family provider=google model=gemini-3.8-flash " +
			"requested=gemini-3.8-flash variant=route in=0 out=0 thinking=0 usd=0.000000 latency_ms=",
	} {
		if !strings.HasPrefix(got[i], want) {
			t.Fatalf("line %d = %q, want prefix %q", i, got[i], want)
		}
	}
	if !strings.HasSuffix(got[0], "outcome=ok fallback=1") || !strings.HasSuffix(got[2], "outcome=error fallback=0") {
		t.Fatalf("outcome and fallback: %q / %q", got[0], got[2])
	}
}
