package llmroute

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	clk := newFakeClock()
	c := NewClient(srv.URL, "k", 30*time.Second)
	c.now = clk.Now
	def := Route{Model: "compiled", ThinkingBudget: -1}

	got := c.Resolve(context.Background(), FamilyJukaHints, def)
	if got.Model != "gemini-3.8-flash" || got.ThinkingBudget != 0 || got.DailyBudgetUSD != 1.5 {
		t.Fatalf("route = %+v", got)
	}
	body.Store(`{"items":[{"family":"juka_hints","model":"gemini-3.5-flash","thinking_budget":-1,"daily_budget_usd":null}]}`)
	if c.Resolve(context.Background(), FamilyJukaHints, def).Model != "gemini-3.8-flash" {
		t.Fatal("cache should hold within the TTL")
	}
	clk.Add(31 * time.Second)
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

func TestEstimateUSDPricesTheFailoverModelWithoutTheStore(t *testing.T) {
	if got := EstimateUSD("gpt-6-luna", 1_000_000, 1_000_000, 0); got < 0.5999 || got > 0.6001 {
		t.Fatalf("gpt-6-luna 1M in + 1M out = %v, want 0.60", got)
	}
	if got := EstimateUSD("unlisted-model", 1_000_000, 0, 0); got != fallbackPrice.in {
		t.Fatalf("unlisted model books at the dearest rate, got %v", got)
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

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1000, 0)} }

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Add(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
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
	clk := newFakeClock()
	c := NewClient(srv.URL, "", 30*time.Second)
	c.now = clk.Now
	def := Route{Model: "d", ThinkingBudget: -1}
	c.Resolve(context.Background(), FamilyJukaLive, def)
	clk.Add(time.Minute)

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

func TestAnEmptyModelsTableDoesNotRefuseEveryRoute(t *testing.T) {
	srv := modelsAndRoutes(`{"items":[]}`, `{"items":[{"family":"juka_live","model":"gemini-x"}]}`, http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	got := c.Resolve(context.Background(), FamilyJukaLive, Route{Model: "d", ThinkingBudget: -1})
	if got.Model != "gemini-x" || got.Provider != ProviderGoogle {
		t.Fatalf("empty models table must not refuse routes, got %+v", got)
	}
}

func TestFamiliesOutsideTheOpenAIAllowlistAreGeminiOnly(t *testing.T) {
	srv := modelsAndRoutes(
		`{"items":[{"model":"listed","provider":"openai"}]}`,
		`{"items":[{"family":"exercise_judge","model":"listed"},{"family":"brand_new","model":"listed"},{"family":"juka_feedback","model":"listed"}]}`,
		http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	def := Route{Model: "gemini-default", ThinkingBudget: -1}
	for _, family := range []string{"exercise_judge", "brand_new"} {
		if got := c.Resolve(context.Background(), family, def); got.Model != "gemini-default" {
			t.Fatalf("%s must stay Gemini, got %+v", family, got)
		}
	}
	if got := c.Resolve(context.Background(), FamilyJukaFeedback, def); got.Provider != ProviderOpenAI {
		t.Fatalf("feedback may use OpenAI, got %+v", got)
	}
}

func TestACancelledCallerDoesNotPoisonTheCache(t *testing.T) {
	srv := modelsAndRoutes(
		`{"items":[{"model":"gemini-x","provider":"google"}]}`,
		`{"items":[{"family":"juka_live","model":"gemini-x"}]}`,
		http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	def := Route{Model: "d", ThinkingBudget: -1}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	c.Resolve(cancelled, FamilyJukaLive, def)
	waitRefresh(t, c)
	if got := c.Resolve(context.Background(), FamilyJukaLive, def); got.Model != "gemini-x" {
		t.Fatalf("a cancelled first caller must not leave defaults in the cache, got %+v", got)
	}
}

func TestACopyOlderThanMaxStaleIsNotServed(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == modelsPath {
			_, _ = w.Write([]byte(`{"items":[{"model":"gemini-a","provider":"google"},{"model":"gemini-b","provider":"google"}]}`))
			return
		}
		model := "gemini-a"
		if atomic.AddInt32(&calls, 1) > 1 {
			<-release
			model = "gemini-b"
		}
		_, _ = w.Write([]byte(`{"items":[{"family":"juka_live","model":"` + model + `"}]}`))
	}))
	defer srv.Close()
	clk := newFakeClock()
	c := NewClient(srv.URL, "", time.Minute)
	c.now = clk.Now
	def := Route{Model: "d", ThinkingBudget: -1}
	c.Resolve(context.Background(), FamilyJukaLive, def)
	clk.Add(maxStale + time.Second)
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	if got := c.Resolve(context.Background(), FamilyJukaLive, def); got.Model != "gemini-b" {
		t.Fatalf("a too-old copy must wait for the refresh, got %+v", got)
	}
}

func TestAllowProvidersDecidesWhichRoutesAProcessServes(t *testing.T) {
	saved := drivable
	t.Cleanup(func() { drivable = saved })
	drivable = map[string]familySet{ProviderOpenAI: {families: OpenAICapableFamilies}}

	if CanDrive("scene_pack", ProviderAnthropic) {
		t.Fatal("a process that declares nothing must not drive Claude")
	}
	AllowProviders([]string{ProviderAnthropic}, "scene_pack")
	if !CanDrive("scene_pack", ProviderAnthropic) || CanDrive("juka_hints", ProviderAnthropic) {
		t.Fatal("family-scoped allowance")
	}
	AllowProviders([]string{ProviderAnthropic})
	if !CanDrive("juka_hints", ProviderAnthropic) {
		t.Fatal("an allowance with no families covers every family")
	}
	AllowProviders([]string{ProviderAnthropic}, "x")
	if !CanDrive("anything", ProviderAnthropic) {
		t.Fatal("a later scoped allowance must not narrow an all-families one")
	}
	if !CanDrive(FamilyJukaLive, ProviderOpenAI) || CanDrive("scene_pack", ProviderOpenAI) {
		t.Fatal("the OpenAI default stays the convo families")
	}
	if InferProvider("claude-haiku-5-5") != ProviderAnthropic {
		t.Fatal("claude- prefix")
	}
}

const canaryModels = `{"items":[` +
	`{"model":"gemini-3.8-flash","provider":"google"},` +
	`{"model":"gemini-3.5-flash","provider":"google"},` +
	`{"model":"claude-haiku-5-5","provider":"anthropic"}]}`

func canaryRoutes(route, candidate string, thinking, share any) string {
	return fmt.Sprintf(`{"items":[{"family":"scene_pack","model":%q,"thinking_budget":768,"daily_budget_usd":2.5,`+
		`"candidate_model":%q,"candidate_thinking_budget":%v,"candidate_share":%v}]}`, route, candidate, thinking, share)
}

func canaryClient(t *testing.T, routes string) *Client {
	t.Helper()
	srv := modelsAndRoutes(canaryModels, routes, http.StatusOK)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "", time.Minute)
}

func withDrivable(t *testing.T, next map[string]familySet) {
	t.Helper()
	drivableMu.Lock()
	saved := drivable
	drivable = next
	drivableMu.Unlock()
	t.Cleanup(func() {
		drivableMu.Lock()
		drivable = saved
		drivableMu.Unlock()
	})
}

func defaultDrivable() map[string]familySet {
	return map[string]familySet{ProviderOpenAI: {families: OpenAICapableFamilies}}
}

var canaryDef = Route{Model: "compiled", ThinkingBudget: -1}

func TestACandidateShareIsPickedByAStableHashOfTheKey(t *testing.T) {
	c := canaryClient(t, canaryRoutes("gemini-3.8-flash", "gemini-3.5-flash", 0, 50))
	ctx := context.Background()
	// crc32("scene_pack:<key>") % 100, the same vector the Python client pins.
	for key, want := range map[string]string{"deck-1": VariantCandidate, "deck-2": VariantRoute, "deck-3": VariantCandidate, "deck-4": VariantRoute} {
		for range 3 {
			if got := c.ResolveKeyed(ctx, "scene_pack", canaryDef, key); got.Variant != want {
				t.Fatalf("key %s: variant %q, want %q", key, got.Variant, want)
			}
		}
	}
	cand := c.ResolveKeyed(ctx, "scene_pack", canaryDef, "deck-1")
	if cand.Model != "gemini-3.5-flash" || cand.Provider != ProviderGoogle || cand.ThinkingBudget != 0 || cand.DailyBudgetUSD != 2.5 {
		t.Fatalf("candidate route = %+v", cand)
	}
	inc := c.ResolveKeyed(ctx, "scene_pack", canaryDef, "deck-2")
	if inc.Model != "gemini-3.8-flash" || inc.ThinkingBudget != 768 || inc.Requested != "" {
		t.Fatalf("incumbent route = %+v", inc)
	}
}

func TestTheHashIsCrc32OfFamilyColonKey(t *testing.T) {
	for _, tc := range []struct {
		family, key string
		bucket      int
	}{{"scene_pack", "deck-1", 15}, {"scene_pack", "ünï-ключ", 6}, {"exercise_judge", "ex-42", 9}} {
		if !inShare(tc.family, tc.key, tc.bucket+1) || inShare(tc.family, tc.key, tc.bucket) {
			t.Fatalf("%s:%s must hash to bucket %d", tc.family, tc.key, tc.bucket)
		}
	}
	if inShare("f", "k", 0) || inShare("f", "", 0) || !inShare("f", "k", 100) {
		t.Fatal("share 0 sends nothing and 100 sends every key")
	}
}

func TestAShareIsHonouredAcrossKeysAndDraws(t *testing.T) {
	c := canaryClient(t, canaryRoutes("gemini-3.8-flash", "gemini-3.5-flash", -1, 20))
	ctx := context.Background()
	keyed, drawn := 0, 0
	for i := range 2000 {
		if c.ResolveKeyed(ctx, "scene_pack", canaryDef, fmt.Sprintf("item-%d", i)).Variant == VariantCandidate {
			keyed++
		}
		if c.Resolve(ctx, "scene_pack", canaryDef).Variant == VariantCandidate {
			drawn++
		}
	}
	for name, n := range map[string]int{"keyed": keyed, "drawn": drawn} {
		if n < 300 || n > 500 {
			t.Fatalf("%s: %d of 2000 went to a 20%% candidate", name, n)
		}
	}
}

func TestShareZeroAndHundred(t *testing.T) {
	ctx := context.Background()
	none := canaryClient(t, canaryRoutes("gemini-3.8-flash", "gemini-3.5-flash", -1, 0))
	all := canaryClient(t, canaryRoutes("gemini-3.8-flash", "gemini-3.5-flash", -1, 100))
	for i := range 50 {
		key := fmt.Sprintf("k%d", i)
		if none.ResolveKeyed(ctx, "scene_pack", canaryDef, key).Variant == VariantCandidate || none.Resolve(ctx, "scene_pack", canaryDef).Variant == VariantCandidate {
			t.Fatal("share 0 must never pick the candidate")
		}
		if all.ResolveKeyed(ctx, "scene_pack", canaryDef, key).Variant != VariantCandidate || all.Resolve(ctx, "scene_pack", canaryDef).Variant != VariantCandidate {
			t.Fatal("share 100 must always pick the candidate")
		}
	}
}

func TestACandidateThisProcessCannotDriveNeverRuns(t *testing.T) {
	withDrivable(t, defaultDrivable())
	c := canaryClient(t, canaryRoutes("gemini-3.8-flash", "claude-haiku-5-5", -1, 100))
	for i := range 20 {
		got := c.ResolveKeyed(context.Background(), "scene_pack", canaryDef, fmt.Sprintf("k%d", i))
		if got.Model != "gemini-3.8-flash" || got.Variant != VariantRoute {
			t.Fatalf("an undrivable candidate must fall to the route, got %+v", got)
		}
	}
	AllowProviders([]string{ProviderAnthropic}, "scene_pack")
	if got := c.ResolveKeyed(context.Background(), "scene_pack", canaryDef, "k"); got.Model != "claude-haiku-5-5" || got.Provider != ProviderAnthropic || got.Variant != VariantCandidate {
		t.Fatalf("a drivable Claude candidate must run, got %+v", got)
	}
}

func TestACandidateMissingFromTheRegistryOrEqualToTheRouteIsIgnored(t *testing.T) {
	ctx := context.Background()
	ghost := canaryClient(t, canaryRoutes("gemini-3.8-flash", "no-such-model", -1, 100))
	if got := ghost.ResolveKeyed(ctx, "scene_pack", canaryDef, "k"); got.Model != "gemini-3.8-flash" || got.Variant != VariantRoute {
		t.Fatalf("ghost candidate: %+v", got)
	}
	same := canaryClient(t, canaryRoutes("gemini-3.8-flash", "gemini-3.8-flash", -1, 100))
	if got := same.ResolveKeyed(ctx, "scene_pack", canaryDef, "k"); got.Variant != VariantRoute {
		t.Fatalf("a candidate equal to the route is no canary: %+v", got)
	}
}

func TestAMalformedCandidateDoesNotBreakTheRouteTable(t *testing.T) {
	srv := modelsAndRoutes(canaryModels, `{"items":[`+
		`{"family":"a","model":"gemini-3.8-flash","candidate_model":"gemini-3.5-flash","candidate_share":"lots"},`+
		`{"family":"b","model":"gemini-3.8-flash","candidate_model":"gemini-3.5-flash","candidate_share":250},`+
		`{"family":"c","model":"gemini-3.8-flash","candidate_model":null,"candidate_share":50},`+
		`{"family":"d","model":"gemini-3.8-flash","candidate_model":"gemini-3.5-flash","candidate_share":50,"candidate_thinking_budget":"x"},`+
		`{"family":"e","model":"gemini-3.8-flash"}]}`, http.StatusOK)
	defer srv.Close()
	c := NewClient(srv.URL, "", time.Minute)
	ctx := context.Background()
	for family, want := range map[string]string{"a": VariantRoute, "b": VariantCandidate, "c": VariantRoute, "d": VariantRoute, "e": VariantRoute} {
		got := c.ResolveKeyed(ctx, family, canaryDef, "k")
		if got.Model == "compiled" || got.Variant != want {
			t.Fatalf("family %s: %+v, want variant %s from the table", family, got, want)
		}
	}
}

func TestARefusedRouteReturnsTheDefaultWithTheRequestedModel(t *testing.T) {
	withDrivable(t, defaultDrivable())
	c := canaryClient(t, canaryRoutes("claude-haiku-5-5", "gemini-3.5-flash", -1, 40))
	ctx := context.Background()
	var cand, def int
	for i := range 200 {
		got := c.ResolveKeyed(ctx, "scene_pack", canaryDef, fmt.Sprintf("k%d", i))
		switch got.Variant {
		case VariantCandidate:
			cand++
		default:
			def++
			if got.Model != "compiled" || got.Requested != "claude-haiku-5-5" {
				t.Fatalf("refused route: want the default asking for claude-haiku-5-5, got %+v", got)
			}
		}
	}
	if cand == 0 || def == 0 {
		t.Fatalf("a candidate still runs beside a refused route: candidate=%d default=%d", cand, def)
	}
	if got := c.Resolve(ctx, "unknown", canaryDef); got != canaryDef {
		t.Fatalf("a family with no row returns the default untouched, got %+v", got)
	}
}

func TestResolveStaysTheRouteWhenThereIsNoCandidate(t *testing.T) {
	srv := modelsAndRoutes(canaryModels, `{"items":[{"family":"scene_pack","model":"gemini-3.8-flash"}]}`, http.StatusOK)
	defer srv.Close()
	got := NewClient(srv.URL, "", time.Minute).ResolveKeyed(context.Background(), "scene_pack", canaryDef, "deck-1")
	if got.Model != "gemini-3.8-flash" || got.Variant != VariantRoute || got.Requested != "" {
		t.Fatalf("route = %+v", got)
	}
}

func TestTheProcessWideResolveKeyedUsesTheConfiguredClient(t *testing.T) {
	srv := modelsAndRoutes(canaryModels, canaryRoutes("gemini-3.8-flash", "gemini-3.5-flash", -1, 50), http.StatusOK)
	defer srv.Close()
	resetCapabilityState(t)
	Configure("svc", srv.URL, "")
	if got := ResolveKeyed(context.Background(), "scene_pack", canaryDef, "deck-1"); got.Variant != VariantCandidate {
		t.Fatalf("deck-1 is in a 50%% share: %+v", got)
	}
	if got := ResolveKeyed(context.Background(), "scene_pack", canaryDef, "deck-2"); got.Variant != VariantRoute {
		t.Fatalf("deck-2 is outside a 50%% share: %+v", got)
	}
	if got := Resolve(context.Background(), "unknown", canaryDef); got != canaryDef {
		t.Fatalf("Resolve keeps working: %+v", got)
	}
}

func TestRecorderCountsOutcomesFallbacksAcceptedAndRejected(t *testing.T) {
	rec := NewRecorder("svc", "http://unused", "")
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond})
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond, Outcome: OutcomeError})
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond, Outcome: OutcomeRefused})
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond, Outcome: OutcomeInvalidOutput})
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond, Error: true})
	rec.Record(Sample{Family: "f", Model: "m", Latency: 10 * time.Millisecond, Fallback: true})
	rec.Record(Sample{Family: "f", Model: "default", Latency: 10 * time.Millisecond, Fallback: true})
	rec.RecordOutcome("f", "m", true, 1)
	rec.RecordOutcome("f", "m", true, 3)
	rec.RecordOutcome("f", "m", false, 2)
	rec.RecordOutcome("f", "m", true, 0)
	rec.RecordOutcome("f", "m", true, -4)
	rec.RecordOutcome("", "m", true, 1)
	rec.RecordOutcome("f", "", true, 1)
	rows := map[string]UsageRow{}
	for _, r := range rec.Drain() {
		rows[r.Model] = r
	}
	m := rows["m"]
	if m.Calls != 6 || m.Errors != 3 || m.Fallbacks != 1 || m.Accepted != 4 || m.Rejected != 2 {
		t.Fatalf("model m row = %+v", m)
	}
	if d := rows["default"]; d.Calls != 1 || d.Fallbacks != 1 || d.Accepted != 0 {
		t.Fatalf("a fallback counts under the model that ran: %+v", d)
	}
}

func TestAnOutcomeOnlyRowSendsNoLatencyAndTheWireCarriesTheCounters(t *testing.T) {
	rec := NewRecorder("svc", "http://unused", "")
	rec.RecordOutcome("f", "m", false, 1)
	rows := rec.Drain()
	if len(rows) != 1 || rows[0].Calls != 0 || rows[0].Rejected != 1 || rows[0].LatencyMsP50 != nil || rows[0].LatencyMsP95 != nil {
		t.Fatalf("outcome-only row = %+v", rows)
	}
	wire, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"accepted":0`, `"rejected":1`, `"fallbacks":0`, `"latency_ms_p50":null`} {
		if !strings.Contains(string(wire), want) {
			t.Fatalf("wire %s lacks %s", wire, want)
		}
	}
	NewRecorder("svc", "", "").RecordOutcome("f", "m", true, 1)
	(*Recorder)(nil).RecordOutcome("f", "m", true, 1)
}

func TestAFailedFlushKeepsOutcomesAndFallbacks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	rec := NewRecorder("svc", srv.URL, "")
	rec.Record(Sample{Family: "f", Model: "m", Fallback: true})
	rec.RecordOutcome("f", "m", true, 2)
	rec.RecordOutcome("f", "m", false, 1)
	if err := rec.Flush(context.Background()); err == nil {
		t.Fatal("a 500 must fail the flush")
	}
	rows := rec.Drain()
	if len(rows) != 1 || rows[0].Calls != 1 || rows[0].Accepted != 2 || rows[0].Rejected != 1 || rows[0].Fallbacks != 1 {
		t.Fatalf("restored rows = %+v", rows)
	}
}

func TestTheProcessWideRecordOutcomeReachesTheRecorder(t *testing.T) {
	RecordOutcome("f", "m", true, 1)
	rec := NewRecorder("svc", "http://unused", "")
	recorderMu.Lock()
	saved := recorder
	recorder = rec
	recorderMu.Unlock()
	t.Cleanup(func() {
		recorderMu.Lock()
		recorder = saved
		recorderMu.Unlock()
	})
	RecordOutcome("f", "m", true, 2)
	Record(Sample{Family: "f", Model: "m", Fallback: true})
	rows := rec.Drain()
	if len(rows) != 1 || rows[0].Accepted != 2 || rows[0].Fallbacks != 1 {
		t.Fatalf("rows = %+v", rows)
	}
}

type capabilityPosts struct {
	mu     sync.Mutex
	bodies []capabilityReport
	keys   []string
	paths  []string
}

func (p *capabilityPosts) snapshot() []capabilityReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]capabilityReport(nil), p.bodies...)
}

func capabilityServer(t *testing.T, status int) (*httptest.Server, *capabilityPosts) {
	t.Helper()
	posts := &capabilityPosts{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		var body capabilityReport
		_ = json.NewDecoder(r.Body).Decode(&body)
		posts.mu.Lock()
		posts.bodies = append(posts.bodies, body)
		posts.keys = append(posts.keys, r.Header.Get("X-Internal-API-Key"))
		posts.paths = append(posts.paths, r.URL.Path)
		posts.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, posts
}

func waitCapabilityIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		capabilityMu.Lock()
		busy := capabilityBusy
		capabilityMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("capability reporter did not finish")
}

func resetCapabilityState(t *testing.T) {
	t.Helper()
	withDrivable(t, defaultDrivable())
	capabilityMu.Lock()
	savedDelay := capabilityDelay
	capabilityDelay = 50 * time.Millisecond
	capabilityMu.Unlock()
	t.Cleanup(func() {
		waitCapabilityIdle(t)
		capabilityMu.Lock()
		capabilityDelay = savedDelay
		capabilityMu.Unlock()
		defaultMu.Lock()
		defaultClient, defaultSvc = nil, ""
		defaultMu.Unlock()
	})
}

func TestCapabilitiesAlwaysListGoogleAndWhatWasDeclared(t *testing.T) {
	withDrivable(t, defaultDrivable())
	body := capabilities("svc")
	if body.Service != "svc" || body.Providers[0].Provider != ProviderGoogle || body.Providers[0].Families != nil {
		t.Fatalf("google first, every family: %+v", body)
	}
	if len(body.Providers) != 2 || body.Providers[1].Provider != ProviderOpenAI || len(body.Providers[1].Families) != len(OpenAICapableFamilies) {
		t.Fatalf("a process that declares nothing reports the OpenAI default: %+v", body)
	}
	AllowProviders([]string{ProviderAnthropic}, "scene_pack", "exercise_judge")
	anth := capabilities("svc").Providers[1]
	if anth.Provider != ProviderAnthropic || strings.Join(anth.Families, ",") != "exercise_judge,scene_pack" {
		t.Fatalf("scoped claude: %+v", anth)
	}
	AllowProviders([]string{ProviderAnthropic, ProviderOpenAI})
	wire, _ := json.Marshal(capabilities("svc"))
	if got := string(wire); got != `{"service":"svc","providers":[{"provider":"google","families":null},{"provider":"anthropic","families":null},{"provider":"openai","families":null}]}` {
		t.Fatalf("wire = %s", got)
	}
}

func TestConfigurePostsTheCapabilitiesOnceFromABackgroundGoroutine(t *testing.T) {
	resetCapabilityState(t)
	srv, posts := capabilityServer(t, http.StatusOK)
	Configure("kielo-convo", srv.URL, "secret")
	if len(posts.snapshot()) != 0 {
		t.Fatal("the report must not block Configure")
	}
	AllowProviders([]string{ProviderAnthropic}) // declared right after start-up
	waitCapabilityIdle(t)
	got := posts.snapshot()
	if len(got) != 1 {
		t.Fatalf("calls close together share one post, got %d", len(got))
	}
	if got[0].Service != "kielo-convo" || posts.keys[0] != "secret" || posts.paths[0] != capabilitiesPath {
		t.Fatalf("post = %+v key=%s path=%s", got[0], posts.keys[0], posts.paths[0])
	}
	names := []string{}
	for _, p := range got[0].Providers {
		names = append(names, p.Provider)
	}
	if strings.Join(names, ",") != "google,anthropic,openai" {
		t.Fatalf("providers = %v", names)
	}
}

func TestDeclaringProvidersLaterSendsAFreshReport(t *testing.T) {
	resetCapabilityState(t)
	srv, posts := capabilityServer(t, http.StatusOK)
	Configure("svc", srv.URL, "")
	AllowProviders([]string{ProviderAnthropic}, "scene_pack")
	waitCapabilityIdle(t)
	AllowProviders([]string{ProviderAnthropic})
	waitCapabilityIdle(t)
	got := posts.snapshot()
	if len(got) != 2 {
		t.Fatalf("want two reports, got %d", len(got))
	}
	families := func(r capabilityReport) []string {
		for _, p := range r.Providers {
			if p.Provider == ProviderAnthropic {
				return p.Families
			}
		}
		return []string{"missing"}
	}
	if strings.Join(families(got[0]), ",") != "scene_pack" || families(got[1]) != nil {
		t.Fatalf("anthropic families = %v then %v", families(got[0]), families(got[1]))
	}
}

func TestNoCapabilityReportWithoutAStoreOrAService(t *testing.T) {
	resetCapabilityState(t)
	srv, posts := capabilityServer(t, http.StatusOK)
	Configure("svc", "", "")
	AllowProviders([]string{ProviderAnthropic})
	Configure("", srv.URL, "")
	AllowProviders([]string{ProviderAnthropic})
	time.Sleep(200 * time.Millisecond)
	capabilityMu.Lock()
	busy := capabilityBusy
	capabilityMu.Unlock()
	if busy || len(posts.snapshot()) != 0 {
		t.Fatalf("nothing to report to: busy=%v posts=%d", busy, len(posts.snapshot()))
	}
}

func TestAFailingCapabilityPostIsSwallowed(t *testing.T) {
	resetCapabilityState(t)
	srv, posts := capabilityServer(t, http.StatusInternalServerError)
	Configure("svc", srv.URL, "")
	waitCapabilityIdle(t)
	if len(posts.snapshot()) != 1 {
		t.Fatal("the post was attempted once")
	}
	if err := NewClient(srv.URL, "", 0).ReportCapabilities(context.Background(), "svc"); err == nil {
		t.Fatal("a 500 is an error to the explicit caller")
	}
	if err := NewClient("", "", 0).ReportCapabilities(context.Background(), "svc"); err != nil {
		t.Fatal("no store means nothing to report")
	}
	if err := (*Client)(nil).ReportCapabilities(context.Background(), "svc"); err != nil {
		t.Fatal("nil client is a no-op")
	}
}
