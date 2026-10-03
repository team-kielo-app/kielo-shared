// Package llmroute is the client for the AI-models control plane
// (docs/architecture/ai-models-control-plane.md). kielo-localization stores one
// route per LLM task family (model, thinking budget, daily budget); every owner
// resolves its model through Resolve and keeps its compiled value as the default.
//
// Like opswitch, Resolve reads an in-process copy of the whole table that
// refreshes at most every TTL (default 30s). When the store cannot be reached the
// last good copy keeps answering; with no copy at all, or a nil / unconfigured
// client, the caller's compiled default is returned (fail-open).
package llmroute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Task family keys. One per row of localization.llm_routes.
const (
	FamilyJukaLive          = "juka_live"
	FamilyJukaFeedback      = "juka_feedback"
	FamilyJukaStepCheck     = "juka_step_check"
	FamilyJukaHints         = "juka_hints"
	FamilyJukaTranslation   = "juka_translation"
	FamilyScenarioAuthoring = "scenario_authoring"
	FamilyExerciseGen       = "exercise_generation"
	FamilyExerciseContext   = "exercise_context_generation"
	FamilyExerciseJudge     = "exercise_judge"
	FamilyExerciseReview    = "exercise_review"
	FamilyTranslationBatch  = "translation_batch"
	FamilyContentIngest     = "content_ingest"
	FamilyWebIngest         = "web_ingest"
	FamilyKTVAI             = "ktv_ai"

	// ThinkingDefault leaves the model's own thinking behavior alone.
	ThinkingDefault = -1

	DefaultTTL = 30 * time.Second

	routesPath     = "/internal/api/v3/localization/llm-routes"
	fetchTimeout   = 2 * time.Second
	maxResponseLen = 1 << 20
)

// Route is what a family resolves to.
type Route struct {
	Model          string
	ThinkingBudget int
	// DailyBudgetUSD is the per-family cap; 0 means no per-family cap.
	DailyBudgetUSD float64
}

type row struct {
	Family         string   `json:"family"`
	Model          string   `json:"model"`
	ThinkingBudget int      `json:"thinking_budget"`
	DailyBudgetUSD *float64 `json:"daily_budget_usd"`
}

// Client reads the route table and caches it.
type Client struct {
	baseURL string
	apiKey  string
	ttl     time.Duration
	http    *http.Client

	mu        sync.Mutex
	routes    map[string]Route
	logged    map[string]string
	fetchedAt time.Time
	now       func() time.Time
}

// NewClient builds a client for kielo-localization at baseURL. ttl <= 0 uses DefaultTTL.
func NewClient(baseURL, internalAPIKey string, ttl time.Duration) *Client {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Client{
		baseURL: strings.TrimSuffix(strings.TrimSpace(baseURL), "/"),
		apiKey:  internalAPIKey,
		ttl:     ttl,
		http:    &http.Client{Timeout: fetchTimeout},
		logged:  map[string]string{},
		now:     time.Now,
	}
}

// Resolve answers the route for family; def fills any gap (no store, unknown
// family, empty model). It never returns an error.
func (c *Client) Resolve(ctx context.Context, family string, def Route) Route {
	if c == nil || c.baseURL == "" {
		return def
	}
	got, ok := c.snapshot(ctx)[family]
	if !ok || strings.TrimSpace(got.Model) == "" {
		return def
	}
	c.noteChange(family, got)
	return got
}

func (c *Client) snapshot(ctx context.Context) map[string]Route {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetchedAt.IsZero() && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.routes
	}
	routes, err := c.fetch(ctx)
	// Stamp failures too so an outage costs one 2s fetch per TTL, not one per call.
	c.fetchedAt = c.now()
	if err == nil {
		c.routes = routes
	}
	return c.routes
}

func (c *Client) noteChange(family string, r Route) {
	sig := fmt.Sprintf("%s|%d|%g", r.Model, r.ThinkingBudget, r.DailyBudgetUSD)
	c.mu.Lock()
	prev, seen := c.logged[family]
	c.logged[family] = sig
	c.mu.Unlock()
	if !seen || prev != sig {
		slog.Info("LLM_ROUTE resolved", "family", family, "model", r.Model,
			"thinking_budget", r.ThinkingBudget, "daily_budget_usd", r.DailyBudgetUSD)
	}
}

func (c *Client) fetch(ctx context.Context) (map[string]Route, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+routesPath, http.NoBody)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseLen))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm-routes: status %d", resp.StatusCode)
	}
	return decodeRoutes(body)
}

func decodeRoutes(body []byte) (map[string]Route, error) {
	var env struct {
		Items []row `json:"items"`
		Data  *struct {
			Items []row `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	items := env.Items
	if env.Data != nil {
		items = env.Data.Items
	}
	out := make(map[string]Route, len(items))
	for _, r := range items {
		route := Route{Model: r.Model, ThinkingBudget: r.ThinkingBudget}
		if r.DailyBudgetUSD != nil {
			route.DailyBudgetUSD = *r.DailyBudgetUSD
		}
		out[r.Family] = route
	}
	return out, nil
}

var (
	defaultMu     sync.RWMutex
	defaultClient *Client
	defaultSvc    string
)

// Configure installs the process-wide client and service name used by Resolve
// and the usage recorder. Empty baseURL leaves every family on its default.
func Configure(service, baseURL, internalAPIKey string) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultClient = NewClient(baseURL, internalAPIKey, DefaultTTL)
	defaultSvc = service
}

// ConfigureFromEnv is Configure with LOCALIZATION_SERVICE_URL and INTERNAL_API_KEY.
func ConfigureFromEnv(service string) {
	key := os.Getenv("INTERNAL_API_KEY") // env-undocumented-exempt: per-service alias compose injects from KIELO_INTERNAL_API_KEY
	if key == "" {
		key = os.Getenv("KIELO_INTERNAL_API_KEY")
	}
	Configure(service, os.Getenv("LOCALIZATION_SERVICE_URL"), key)
}

// Service is the service name given to Configure.
func Service() string {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultSvc
}

// Resolve answers the route for family through the process-wide client.
func Resolve(ctx context.Context, family string, def Route) Route {
	defaultMu.RLock()
	c := defaultClient
	defaultMu.RUnlock()
	return c.Resolve(ctx, family, def)
}

// Model is Resolve(...).Model with the compiled default for the model name.
func Model(ctx context.Context, family, defaultModel string) string {
	return Resolve(ctx, family, Route{Model: defaultModel, ThinkingBudget: ThinkingDefault}).Model
}
