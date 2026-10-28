// Package jev is a thin client for TypeSafe AI's Jev ("System One") model. Jev writes no text: it answers typed
// questions about text or JSON with a choice, a score or a 0-1 truth value, each with a calibrated confidence.
//
// Every failure (no key, timeout, error, refused spend) yields nil answers so the caller falls back to its current check.
//
// PROVISIONAL WIRE SHAPE: TypeSafe's request and response are not documented anywhere we can read. The shape below is
// our own minimal typed contract and must be reconciled with the real API before any call site relies on it.
//
//	POST {JEV_BASE_URL}/v1/systemone   Authorization: Bearer {JEV_API_KEY}
//	{"state": <string|json>, "questions": [{"id","kind","prompt","options"?}]}
//	-> {"model": "...", "usage": {"input_tokens": N}, "answers": {"<id>": {"value": ..., "confidence": 0-1}}}
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/team-kielo-app/kielo-shared/llmroute"
)

const (
	EnvAPIKey  = "JEV_API_KEY"
	EnvBaseURL = "JEV_BASE_URL"
	EnvTimeout = "JEV_TIMEOUT_S"
	// EnvUSDPerMTok is the provisional price per million input tokens booked on the spend guard.
	EnvUSDPerMTok = "JEV_USD_PER_MTOK"

	DefaultTimeout   = 1500 * time.Millisecond
	DefaultUSDPerTok = 1.0
	Path             = "/v1/systemone"
	FamilyPrefix     = "jev_"
	maxResponseBytes = 1 << 20
)

// Kind is the type of answer a question asks for.
type Kind string

const (
	KindChoice Kind = "choice"
	KindScore  Kind = "score"
	KindTruth  Kind = "truth"
)

// Question is one typed question. Options applies to KindChoice (up to 255).
type Question struct {
	ID      string   `json:"id"`
	Kind    Kind     `json:"kind"`
	Prompt  string   `json:"prompt"`
	Options []string `json:"options,omitempty"`
}

// Answer is Jev's answer: a chosen option (string), a score or a truth value (number), plus its confidence.
type Answer struct {
	Value      any     `json:"value"`
	Confidence float64 `json:"confidence"`
}

// Answers maps question id to its answer.
type Answers map[string]Answer

// Decider is what call sites depend on, so tests can swap in a Fake.
type Decider interface {
	Decide(ctx context.Context, site string, state any, questions []Question) Answers
}

type request struct {
	State     any        `json:"state"`
	Questions []Question `json:"questions"`
}

type response struct {
	Model string `json:"model"`
	Usage struct {
		InputTokens int64 `json:"input_tokens"`
	} `json:"usage"`
	Answers Answers `json:"answers"`
}

// Client calls Jev over HTTP.
type Client struct {
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	USDPerMTok float64
	HTTP       *http.Client
}

// FromEnv reads JEV_API_KEY, JEV_BASE_URL, JEV_TIMEOUT_S and JEV_USD_PER_MTOK.
func FromEnv() *Client {
	c := &Client{
		APIKey:     strings.TrimSpace(os.Getenv(EnvAPIKey)),
		BaseURL:    strings.TrimRight(strings.TrimSpace(os.Getenv(EnvBaseURL)), "/"),
		Timeout:    DefaultTimeout,
		USDPerMTok: DefaultUSDPerTok,
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvTimeout)), 64); err == nil && v > 0 {
		c.Timeout = time.Duration(v * float64(time.Second))
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvUSDPerMTok)), 64); err == nil && v >= 0 {
		c.USDPerMTok = v
	}
	return c
}

// Enabled reports whether a key and base URL are configured.
func (c *Client) Enabled() bool {
	return c != nil && c.APIKey != "" && c.BaseURL != ""
}

var budgetFor = func(ctx context.Context, family string) float64 {
	return llmroute.Resolve(ctx, family, llmroute.Route{}).DailyBudgetUSD
}

// Family is the spend-guard family for a call site.
func Family(site string) string { return FamilyPrefix + site }

// Decide asks questions about state and returns answers, or nil on any failure. It never panics or errors into the caller.
func (c *Client) Decide(ctx context.Context, site string, state any, questions []Question) (out Answers) {
	if !c.Enabled() || len(questions) == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("jev: recovered", "site", site, "panic", fmt.Sprint(r))
			out = nil
		}
	}()
	family := Family(site)
	if err := llmroute.Admit(family, budgetFor(ctx, family)); err != nil {
		slog.Warn("jev: spend refused", "site", site, "error", err)
		return nil
	}
	res, latency, err := c.post(ctx, state, questions)
	if err != nil {
		slog.Warn("jev: call failed", "site", site, "latency_ms", latency.Milliseconds(), "error", err)
		return nil
	}
	usd := float64(res.Usage.InputTokens) * c.USDPerMTok / 1e6
	llmroute.Book(family, usd)
	llmroute.Record(llmroute.Sample{Family: family, Model: res.Model, Latency: latency, InputTokens: res.Usage.InputTokens, USD: usd})
	slog.Info("jev: decided", "site", site, "model", res.Model, "latency_ms", latency.Milliseconds(), "input_tokens", res.Usage.InputTokens)
	return res.Answers
}

func (c *Client) post(ctx context.Context, state any, questions []Question) (*response, time.Duration, error) {
	body, err := json.Marshal(request{State: state, Questions: questions})
	if err != nil {
		return nil, 0, fmt.Errorf("encode: %w", err)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+Path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	started := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, time.Since(started), fmt.Errorf("send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	latency := time.Since(started)
	if err != nil {
		return nil, latency, fmt.Errorf("read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, latency, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, latency, fmt.Errorf("decode: %w", err)
	}
	return &out, latency, nil
}

// Decide is the package-level shape: one call through a client built from the environment.
func Decide(ctx context.Context, site string, state any, questions []Question) Answers {
	return FromEnv().Decide(ctx, site, state, questions)
}

// ShadowEnabled reports whether JEV_SHADOW_<SITE>=1 and a key is set.
func ShadowEnabled(site string) bool {
	if strings.TrimSpace(os.Getenv("JEV_SHADOW_"+strings.ToUpper(site))) != "1" {
		return false
	}
	return strings.TrimSpace(os.Getenv(EnvAPIKey)) != ""
}

// Fake returns canned answers keyed by question id. Questions it has no answer for are omitted.
type Fake struct {
	Canned Answers
	Calls  int
}

// Decide implements Decider.
func (f *Fake) Decide(_ context.Context, _ string, _ any, questions []Question) Answers {
	f.Calls++
	out := Answers{}
	for _, q := range questions {
		if a, ok := f.Canned[q.ID]; ok {
			out[q.ID] = a
		}
	}
	return out
}
