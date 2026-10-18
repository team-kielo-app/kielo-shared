package llmroute

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func routesServer(t *testing.T, body *atomic.Value, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if r.Header.Get("X-Internal-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == modelsPath {
			_, _ = w.Write([]byte(`{"items":[{"model":"gemini-3.8-flash","provider":"google"},{"model":"gemini-3.5-flash","provider":"google"}]}`))
			return
		}
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
}

func TestResolveFollowsStoreWithinTTL(t *testing.T) {
	var body atomic.Value
	body.Store(`{"items":[{"family":"juka_hints","model":"gemini-3.8-flash","thinking_budget":0,"daily_budget_usd":1.5}]}`)
	var hits int32
	srv := routesServer(t, &body, &hits)
	defer srv.Close()
	now := time.Unix(1000, 0)
	c := NewClient(srv.URL, "k", 30*time.Second)
	c.now = func() time.Time { return now }
	def := Route{Model: "compiled", ThinkingBudget: -1}

	got := c.Resolve(context.Background(), FamilyJukaHints, def)
	if got.Model != "gemini-3.8-flash" || got.ThinkingBudget != 0 || got.DailyBudgetUSD != 1.5 {
		t.Fatalf("route = %+v", got)
	}
	body.Store(`{"items":[{"family":"juka_hints","model":"gemini-3.5-flash","thinking_budget":-1,"daily_budget_usd":null}]}`)
	if c.Resolve(context.Background(), FamilyJukaHints, def).Model != "gemini-3.8-flash" {
		t.Fatal("cache should hold within the TTL")
	}
	now = now.Add(31 * time.Second)
	if got := c.Resolve(context.Background(), FamilyJukaHints, def); got.Model != "gemini-3.8-flash" {
		t.Fatalf("a stale copy keeps answering while it refreshes, got %+v", got)
	}
	waitRefresh(t, c)
	if got := c.Resolve(context.Background(), FamilyJukaHints, def); got.Model != "gemini-3.5-flash" || got.DailyBudgetUSD != 0 {
		t.Fatalf("after TTL = %+v", got)
	}
	if got := c.Resolve(context.Background(), "unknown_family", def); got != def {
		t.Fatalf("unknown family should fall back to default, got %+v", got)
	}
}

func TestResolveFailsOpen(t *testing.T) {
	def := Route{Model: "compiled", ThinkingBudget: -1}
	if got := (*Client)(nil).Resolve(context.Background(), "x", def); got != def {
		t.Fatal("nil client must return the default")
	}
	if got := NewClient("", "k", 0).Resolve(context.Background(), "x", def); got != def {
		t.Fatal("empty URL must return the default")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	if got := NewClient(srv.URL, "k", 0).Resolve(context.Background(), "x", def); got != def {
		t.Fatal("a failing store must return the default")
	}
}

func TestSpendAdmitBooksPerFamily(t *testing.T) {
	s := NewSpend()
	if err := s.Admit("f", 0.01); err != nil {
		t.Fatal(err)
	}
	s.Book("f", 0.02)
	if err := s.Admit("f", 0.01); err == nil {
		t.Fatal("budget reached should refuse")
	}
	if err := s.Admit("other", 0.01); err != nil {
		t.Fatal("other family is independent")
	}
	if err := s.Admit("f", 0); err != nil {
		t.Fatal("zero budget means no cap")
	}
}

func TestRecorderAggregatesAndFlushes(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		got.Store(string(buf[:n]))
	}))
	defer srv.Close()
	rec := NewRecorder("svc", srv.URL, "k")
	for i := 1; i <= 100; i++ {
		rec.Record(Sample{Family: "juka_hints", Model: "m", InputTokens: 10, OutputTokens: 5, USD: 0.001, Latency: time.Duration(i) * time.Millisecond, Error: i%50 == 0})
	}
	rows := rec.Drain()
	if len(rows) != 1 || rows[0].Calls != 100 || rows[0].Errors != 2 || rows[0].InputTokens != 1000 {
		t.Fatalf("rows = %+v", rows)
	}
	if *rows[0].LatencyMsP50 != 50 || *rows[0].LatencyMsP95 != 95 {
		t.Fatalf("p50/p95 = %d/%d", *rows[0].LatencyMsP50, *rows[0].LatencyMsP95)
	}
	rec.Record(Sample{Family: "juka_hints", Model: "m", Latency: time.Millisecond})
	if err := rec.Flush(context.Background()); err != nil || got.Load() == nil {
		t.Fatalf("flush err=%v body=%v", err, got.Load())
	}
	NewRecorder("svc", "", "").Record(Sample{Family: "x"})
}

func TestResolveCarriesProviderFromModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == modelsPath {
			_, _ = w.Write([]byte(`{"items":[{"model":"listed-model","provider":"openai"},{"model":"gemini-x","provider":"google"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[` +
			`{"family":"juka_live","model":"listed-model","thinking_budget":-1},` +
			`{"family":"juka_hints","model":"gemini-x","thinking_budget":-1}]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "", 30*time.Second)
	def := Route{Model: "gemini-default", ThinkingBudget: -1}

	if got := c.Resolve(context.Background(), FamilyJukaLive, def); got.Provider != ProviderOpenAI {
		t.Fatalf("listed model provider = %q", got.Provider)
	}
	if got := c.Resolve(context.Background(), FamilyJukaHints, def); got.Provider != ProviderGoogle {
		t.Fatalf("listed google model, got %q", got.Provider)
	}
	if got := c.Resolve(context.Background(), "unknown_family", def); got.Provider != ProviderGoogle {
		t.Fatalf("default route should infer from the default model, got %q", got.Provider)
	}
}

func waitRefresh(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		busy := c.refreshing
		c.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("refresh did not finish")
}

func modelsAndRoutes(models, routes string, modelsStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == modelsPath {
			if modelsStatus != http.StatusOK {
				w.WriteHeader(modelsStatus)
				return
			}
			_, _ = w.Write([]byte(models))
			return
		}
		_, _ = w.Write([]byte(routes))
	}))
}

func TestResolveRefusesAMissingOrInactiveModel(t *testing.T) {
	srv := modelsAndRoutes(
		`{"items":[{"model":"listed","provider":"openai","active":true},{"model":"retired","provider":"openai","active":false}]}`,
		`{"items":[{"family":"juka_live","model":"retired"},{"family":"juka_feedback","model":"ghost"},{"family":"juka_step_check","model":"listed"}]}`,
		http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	def := Route{Model: "gemini-default", ThinkingBudget: -1}
	for _, family := range []string{FamilyJukaLive, FamilyJukaFeedback} {
		if got := c.Resolve(context.Background(), family, def); got.Model != "gemini-default" {
			t.Fatalf("%s should fall back, got %+v", family, got)
		}
	}
	if got := c.Resolve(context.Background(), FamilyJukaStepCheck, def); got.Provider != ProviderOpenAI {
		t.Fatalf("listed active model should serve, got %+v", got)
	}
}

func TestResolveInfersProviderOnlyWhenModelsNeverLoaded(t *testing.T) {
	srv := modelsAndRoutes("", `{"items":[{"family":"juka_live","model":"gpt-x"}]}`, http.StatusInternalServerError)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	def := Route{Model: "gemini-default", ThinkingBudget: -1}
	if got := c.Resolve(context.Background(), FamilyJukaLive, def); got.Model != "gpt-x" || got.Provider != ProviderOpenAI {
		t.Fatalf("routes up, models down at cold start should infer, got %+v", got)
	}
}

func TestGeminiOnlyFamilyRefusesAnOpenAIRoute(t *testing.T) {
	srv := modelsAndRoutes(
		`{"items":[{"model":"listed","provider":"openai"}]}`,
		`{"items":[{"family":"juka_hints","model":"listed"},{"family":"juka_live","model":"listed"}]}`,
		http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	def := Route{Model: "gemini-default", ThinkingBudget: -1}
	if got := c.Resolve(context.Background(), FamilyJukaHints, def); got.Model != "gemini-default" {
		t.Fatalf("hints cannot drive OpenAI, got %+v", got)
	}
	if got := c.Resolve(context.Background(), FamilyJukaLive, def); got.Provider != ProviderOpenAI {
		t.Fatalf("live may, got %+v", got)
	}
}

func TestSnapshotDoesNotHoldTheLockWhileFetching(t *testing.T) {
	release := make(chan struct{})
	var first int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == modelsPath {
			_, _ = w.Write([]byte(`{"items":[{"model":"gemini-3.8-flash","provider":"google"}]}`))
			return
		}
		if atomic.AddInt32(&first, 1) > 1 {
			<-release
		}
		_, _ = w.Write([]byte(`{"items":[{"family":"juka_live","model":"gemini-3.8-flash"}]}`))
	}))
	defer srv.Close()
	defer close(release)
	now := time.Unix(1000, 0)
	c := NewClient(srv.URL, "", 30*time.Second)
	c.now = func() time.Time { return now }
	def := Route{Model: "d", ThinkingBudget: -1}
	c.Resolve(context.Background(), FamilyJukaLive, def)
	now = now.Add(time.Minute)

	done := make(chan Route, 1)
	go func() { done <- c.Resolve(context.Background(), FamilyJukaLive, def) }()
	select {
	case got := <-done:
		if got.Model != "gemini-3.8-flash" {
			t.Fatalf("stale copy expected, got %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Resolve blocked on a slow refresh")
	}
}
