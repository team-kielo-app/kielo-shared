package opswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func str(s string) *string { return &s }

func TestEvaluate(t *testing.T) {
	rows := []Row{
		{SwitchKey: KeyKTVFeed, ScopeType: ScopeGlobal, Enabled: true},
		{SwitchKey: KeyKTVFeed, ScopeType: ScopeLanguage, ScopeValue: "fi", Enabled: false, Message: str("  Finnish TV is resting  ")},
		{SwitchKey: KeyKTVFeed, ScopeType: ScopePlatform, ScopeValue: "ios", Enabled: false},
		{SwitchKey: KeyConvoCalls, ScopeType: ScopeGlobal, Enabled: false},
	}
	if d := Evaluate(rows, KeyKTVFeed, Scope{Language: "sv", Platform: "android"}); d.Off {
		t.Fatalf("unrelated scope must stay on: %+v", d)
	}
	d := Evaluate(rows, KeyKTVFeed, Scope{Language: "FI", Platform: "ios"})
	if !d.Off || d.Message != "Finnish TV is resting" || !d.Custom || d.ScopeType != ScopeLanguage {
		t.Fatalf("language row should win: %+v", d)
	}
	if d := Evaluate(rows, KeyKTVFeed, Scope{Platform: "ios"}); !d.Off || d.Message != DefaultMessage || d.Custom {
		t.Fatalf("platform row should give default message: %+v", d)
	}
	if d := Evaluate(rows, KeyConvoCalls, Scope{}); !d.Off {
		t.Fatalf("global off applies everywhere: %+v", d)
	}
	if d := Evaluate(rows, KeyPushCampaigns, Scope{}); d.Off {
		t.Fatalf("unknown key reads as on: %+v", d)
	}
}

func TestClientCachesAndFailsOpen(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Internal-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"items":[{"switch_key":"convo.calls","scope_type":"global","scope_value":"","enabled":false}]}}`))
	}))
	defer srv.Close()

	now := time.Now()
	c := NewClient(srv.URL, "k", 30*time.Second)
	c.now = func() time.Time { return now }
	ctx := context.Background()

	if !c.Check(ctx, KeyConvoCalls, Scope{}).Off {
		t.Fatal("switch should read off")
	}
	if !c.Check(ctx, KeyConvoCalls, Scope{}).Off {
		t.Fatal("cached switch should read off")
	}
	if hits.Load() != 1 {
		t.Fatalf("second check must hit the cache, hits=%d", hits.Load())
	}
	fail.Store(true)
	now = now.Add(31 * time.Second)
	if !c.Check(ctx, KeyConvoCalls, Scope{}).Off {
		t.Fatal("last good copy must keep answering when the store fails")
	}

	cold := NewClient(srv.URL, "wrong", 0)
	if cold.Check(ctx, KeyConvoCalls, Scope{}).Off {
		t.Fatal("no copy ever loaded must fail open")
	}
	var nilClient *Client
	if nilClient.Check(ctx, KeyConvoCalls, Scope{}).Off || NewClient("", "", 0).Check(ctx, KeyConvoCalls, Scope{}).Off {
		t.Fatal("nil or unconfigured client reads as on")
	}
}

func TestClientOutageWithNoCopyCostsOneFetchPerTTL(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "k", time.Minute)
	for i := 0; i < 5; i++ {
		if c.Check(context.Background(), KeyKTVFeed, Scope{}).Off {
			t.Fatal("store outage must read as on")
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}
