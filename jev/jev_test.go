package jev

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/team-kielo-app/kielo-shared/llmroute"
)

var qs = []Question{{ID: "ok", Kind: KindTruth, Prompt: "Is the key correct?"}}

func client(url string) *Client {
	return &Client{APIKey: "k", BaseURL: url, Timeout: time.Second, USDPerMTok: 2}
}

func TestNoKeyReturnsNilWithoutCalling(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvBaseURL, srv.URL)
	if got := Decide(context.Background(), "s", "text", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
	if hits != 0 {
		t.Fatalf("made %d calls without a key", hits)
	}
}

func TestHappyPathRealShapesAndSpend(t *testing.T) {
	llmroute.ResetSpend()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"model":"jev-1.14.0","usage":{"input_tokens":500000,"output_tokens":9},"answers":{
			"ok":{"type":"noul","noul":0.9},
			"sev":{"type":"choice","choice":"high","confidence":0.7,"probabilities":{"low":0.1,"high":0.9}},
			"fit":{"type":"score","score":4,"confidence":0.6,"probabilities":{"4":0.6},"legend":"x"}}}`))
	}))
	defer srv.Close()
	all := []Question{
		qs[0],
		{ID: "sev", Kind: KindChoice, Prompt: "Severity?", Options: []string{"low", "high"}, Descriptions: map[string]string{"low": "minor"}},
		{ID: "fit", Kind: KindScore, Prompt: "Fit?", Options: []string{"1", "2"}},
	}
	c := client(srv.URL)
	c.Model, c.USDPerMTok = DefaultModel, 0.042
	out := c.Decide(context.Background(), "exercise_publish", "text", all)
	if a := out["ok"]; a.Value.(float64) != 0.9 || a.Confidence != nil || a.Conf() != 0.9 {
		t.Fatalf("noul answer %+v", a)
	}
	if a := out["sev"]; a.Value != "high" || *a.Confidence != 0.7 || a.Probabilities["high"] != 0.9 {
		t.Fatalf("choice answer %+v", a)
	}
	if a := out["fit"]; a.Value.(float64) != 4 || *a.Confidence != 0.6 {
		t.Fatalf("score answer %+v", a)
	}
	if got["model"] != "jev-1.14.0" {
		t.Fatalf("model %v", got["model"])
	}
	q := got["questions"].(map[string]any)
	ok, sev, fit := q["ok"].(map[string]any), q["sev"].(map[string]any), q["fit"].(map[string]any)
	if ok["type"] != "noul" || ok["instructions"] != "Is the key correct?" || ok["criteria"] != nil {
		t.Fatalf("noul question %v", ok)
	}
	crit := sev["criteria"].(map[string]any)
	if sev["type"] != "choice" || crit["low"] != "minor" || crit["high"] != nil {
		t.Fatalf("choice question %v", sev)
	}
	if fit["type"] != "score" || len(fit["criteria"].([]any)) != 2 {
		t.Fatalf("score question %v", fit)
	}
	want := 500000 * 0.042 / 1e6
	if spent := llmroute.Spent("jev_exercise_publish"); spent < want*0.999 || spent > want*1.001 {
		t.Fatalf("booked %v, want %v under jev_exercise_publish", spent, want)
	}
}

func TestRateLimitReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer srv.Close()
	if got := client(srv.URL).Decide(context.Background(), "s", "t", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv(EnvBaseURL, "")
	t.Setenv(EnvModel, "")
	t.Setenv(EnvUSDPerMTok, "")
	c := FromEnv()
	if c.BaseURL != "https://api.typesafe.ai" || c.Model != "jev-1.14.0" || c.USDPerMTok != 0.042 {
		t.Fatalf("defaults %+v", c)
	}
	t.Setenv(EnvModel, "jev-9")
	if FromEnv().Model != "jev-9" {
		t.Fatal("JEV_MODEL not honoured")
	}
}

func TestErrorStatusReturnsNil(t *testing.T) {
	llmroute.ResetSpend()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	if got := client(srv.URL).Decide(context.Background(), "s", "t", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
	if llmroute.Spent("jev_s") != 0 {
		t.Fatal("a failed call must not book spend")
	}
}

func TestBadJSONReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("nope")) }))
	defer srv.Close()
	if got := client(srv.URL).Decide(context.Background(), "s", "t", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestTimeoutReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	c := client(srv.URL)
	c.Timeout = 50 * time.Millisecond
	started := time.Now()
	if got := c.Decide(context.Background(), "s", "t", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
	if time.Since(started) > time.Second {
		t.Fatal("timeout not honoured")
	}
}

func TestSpendRefusedReturnsNilWithoutCalling(t *testing.T) {
	llmroute.ResetSpend()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	llmroute.Book("jev_s", 5)
	prev := budgetFor
	budgetFor = func(context.Context, string) float64 { return 1 }
	defer func() { budgetFor = prev }()
	if got := client(srv.URL).Decide(context.Background(), "s", "t", qs); got != nil || hits != 0 {
		t.Fatalf("over-budget family must not call: got %v hits %d", got, hits)
	}
}

func TestFromEnvTimeout(t *testing.T) {
	t.Setenv(EnvTimeout, "0.25")
	if got := FromEnv().Timeout; got != 250*time.Millisecond {
		t.Fatalf("got %v", got)
	}
	t.Setenv(EnvTimeout, "")
	if got := FromEnv().Timeout; got != DefaultTimeout {
		t.Fatalf("got %v", got)
	}
}

func TestShadowEnabled(t *testing.T) {
	t.Setenv("JEV_SHADOW_STORE_REVIEW_TRIAGE", "1")
	t.Setenv(EnvAPIKey, "")
	if ShadowEnabled("store_review_triage") {
		t.Fatal("no key must disable")
	}
	t.Setenv(EnvAPIKey, "k")
	if !ShadowEnabled("store_review_triage") {
		t.Fatal("flag and key must enable")
	}
}

func TestFake(t *testing.T) {
	conf := 0.9
	f := &Fake{Canned: Answers{"ok": {Value: "a", Confidence: &conf}}}
	got := f.Decide(context.Background(), "s", "t", append(qs, Question{ID: "other"}))
	if len(got) != 1 || *got["ok"].Confidence != 0.9 || f.Calls != 1 {
		t.Fatalf("got %v", got)
	}
}

type usageSink struct {
	mu    sync.Mutex
	lines []string
}

func (u *usageSink) Enabled(context.Context, slog.Level) bool { return true }
func (u *usageSink) Handle(_ context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "LLM_USAGE ") {
		u.mu.Lock()
		u.lines = append(u.lines, r.Message)
		u.mu.Unlock()
	}
	return nil
}
func (u *usageSink) WithAttrs([]slog.Attr) slog.Handler { return u }
func (u *usageSink) WithGroup(string) slog.Handler      { return u }

func TestEveryJevCallLogsOneUsageLineWithProviderAndOutcome(t *testing.T) {
	llmroute.ResetSpend()
	sink := &usageSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"jev-1.14.0","usage":{"input_tokens":1000},"answers":{"ok":{"type":"noul","noul":0.9}}}`))
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer down.Close()

	good := client(ok.URL)
	good.Model = DefaultModel
	if got := good.Decide(context.Background(), "exercise_publish", "text", qs); got == nil {
		t.Fatal("the happy path must answer")
	}
	if got := client(down.URL).Decide(context.Background(), "exercise_publish", "text", qs); got != nil {
		t.Fatalf("want nil, got %v", got)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.lines) != 2 {
		t.Fatalf("want a line for the answer and one for the failure, got %v", sink.lines)
	}
	for i, want := range []string{
		"family=jev_exercise_publish provider=typesafe model=jev-1.14.0 requested=jev-1.14.0 variant=route in=1000 out=0 thinking=0 usd=0.002000 ",
		"family=jev_exercise_publish provider=typesafe model=jev-1.14.0 requested=jev-1.14.0 variant=route in=0 out=0 thinking=0 usd=0.000000 ",
	} {
		if !strings.Contains(sink.lines[i], want) {
			t.Fatalf("line %d = %q lacks %q", i, sink.lines[i], want)
		}
	}
	if !strings.HasSuffix(sink.lines[0], "outcome=ok fallback=0") || !strings.HasSuffix(sink.lines[1], "outcome=error fallback=0") {
		t.Fatalf("outcomes: %q / %q", sink.lines[0], sink.lines[1])
	}
}
