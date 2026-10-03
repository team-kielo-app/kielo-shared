package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/team-kielo-app/kielo-shared/llmroute"
)

type fakeProvider struct{ last Request }

func (f *fakeProvider) Generate(_ context.Context, req Request) (*Result, error) {
	f.last = req
	return &Result{RawText: "{}", InputTokens: 1000, OutputTokens: 500, ThinkingTokens: 500}, nil
}

func TestRoutingAppliesRouteAndBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
