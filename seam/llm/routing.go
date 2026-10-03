package llm

import (
	"context"
	"time"

	"github.com/team-kielo-app/kielo-shared/llmroute"
)

// RoutingDecorator applies the AI-models control plane to a Provider: a request
// with a Family gets its model and thinking budget from llmroute (the request's
// own Model is the compiled default), is refused once the family's daily budget
// is spent, and every call is rolled up per (service, family, model).
type RoutingDecorator struct {
	Inner Provider
}

// WithRouting wraps inner with control-plane routing. Requests without a Family pass through.
func WithRouting(inner Provider) *RoutingDecorator { return &RoutingDecorator{Inner: inner} }

// ProviderID forwards to the inner provider so metrics keep splitting by model.
func (d *RoutingDecorator) ProviderID(req Request) string {
	if p, ok := d.Inner.(interface{ ProviderID(Request) string }); ok {
		return p.ProviderID(req)
	}
	return "llm:unknown"
}

func (d *RoutingDecorator) Generate(ctx context.Context, req Request) (*Result, error) {
	if req.Family == "" {
		return d.Inner.Generate(ctx, req)
	}
	def := llmroute.Route{Model: req.Model, ThinkingBudget: llmroute.ThinkingDefault}
	if req.ThinkingBudget != nil {
		def.ThinkingBudget = *req.ThinkingBudget
	}
	route := llmroute.Resolve(ctx, req.Family, def)
	req.Model = route.Model
	if route.ThinkingBudget >= 0 {
		b := route.ThinkingBudget
		req.ThinkingBudget = &b
	}
	if err := llmroute.Admit(req.Family, route.DailyBudgetUSD); err != nil {
		return nil, &Error{Class: ErrorClassClientError, Err: err}
	}
	started := time.Now()
	res, err := d.Inner.Generate(ctx, req)
	sample := llmroute.Sample{Family: req.Family, Model: req.Model, Latency: time.Since(started), Error: err != nil}
	if res != nil {
		sample.InputTokens, sample.OutputTokens, sample.ThinkingTokens = res.InputTokens, res.OutputTokens, res.ThinkingTokens
		sample.USD = llmroute.EstimateUSD(req.Model, res.InputTokens, res.OutputTokens, res.ThinkingTokens)
		llmroute.Book(req.Family, sample.USD)
	}
	llmroute.Record(sample)
	return res, err
}
