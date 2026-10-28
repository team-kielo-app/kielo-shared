package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestHappyPathBooksSpend(t *testing.T) {
	llmroute.ResetSpend()
	var gotBody request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"model":"jev-1","usage":{"input_tokens":500000},"answers":{"ok":{"value":0.9,"confidence":0.8}}}`))
	}))
	defer srv.Close()
	got := client(srv.URL).Decide(context.Background(), "exercise_publish", "text", qs)
	if a, ok := got["ok"]; !ok || a.Confidence != 0.8 || a.Value.(float64) != 0.9 {
		t.Fatalf("unexpected answers %v", got)
	}
	if len(gotBody.Questions) != 1 || gotBody.Questions[0].Kind != KindTruth {
		t.Fatalf("unexpected request %+v", gotBody)
	}
	if spent := llmroute.Spent("jev_exercise_publish"); spent != 1.0 {
		t.Fatalf("booked %v, want 1.0 under family jev_exercise_publish", spent)
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
	f := &Fake{Canned: Answers{"ok": {Value: 1.0, Confidence: 0.9}}}
	got := f.Decide(context.Background(), "s", "t", append(qs, Question{ID: "other"}))
	if len(got) != 1 || got["ok"].Confidence != 0.9 || f.Calls != 1 {
		t.Fatalf("got %v", got)
	}
}
