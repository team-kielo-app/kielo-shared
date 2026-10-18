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

	routesPath = "/internal/api/v3/localization/llm-routes"
	modelsPath = "/internal/api/v3/localization/llm-models"

	ProviderGoogle = "google"
	ProviderOpenAI = "openai"
	fetchTimeout   = 2 * time.Second
	maxResponseLen = 1 << 20
)

// Route is what a family resolves to.
type Route struct {
	Model          string
	ThinkingBudget int
	// DailyBudgetUSD is the per-family cap; 0 means no per-family cap.
	DailyBudgetUSD float64
	// Provider is llm_models.provider of Model ("google", "openai"); empty
	// when neither the store nor the model name says.
	Provider string
}

// providerByPrefix is the last resort when llm_models has no row for a routed
// model: the model-name family decides.
var providerByPrefix = []struct{ prefix, provider string }{
	{"gemini-", ProviderGoogle},
	{"gpt-", ProviderOpenAI},
}

// InferProvider names the provider from the model name alone, "" when unknown.
func InferProvider(model string) string {
	name := strings.ToLower(strings.TrimSpace(model))
	for _, p := range providerByPrefix {
		if strings.HasPrefix(name, p.prefix) {
			return p.provider
		}
	}
	return ""
}

type modelRow struct {
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Active   *bool  `json:"active"`
}

type modelInfo struct {
	provider string
	active   bool
}

type row struct {
	Provider       string   `json:"provider"`
	Family         string   `json:"family"`
	Model          string   `json:"model"`
	ThinkingBudget int      `json:"thinking_budget"`
	DailyBudgetUSD *float64 `json:"daily_budget_usd"`
}

// OpenAICapableFamilies are the families whose call sites can drive an OpenAI
// model (the convo agent's routed_llm and LiveKit builder). Every other family
// (the engine's Gemini client, ingest, the Go Gemini seam, KTV, hints,
// translation, scenario authoring) can only drive Gemini, so a new family is
// Gemini-only by default: a route naming another provider for it is refused and
// the caller's compiled default runs, logged once.
var OpenAICapableFamilies = map[string]bool{
	FamilyJukaLive:      true,
	FamilyJukaFeedback:  true,
	FamilyJukaStepCheck: true,
}

// maxStale bounds how long a stale copy keeps answering while a refresh runs;
// past it callers wait (up to their context) for the refresh.
const maxStale = 5 * time.Minute

type tables struct {
	routes       map[string]Route
	models       map[string]modelInfo
	modelsLoaded bool
}

// Client reads the route table and caches it.
type Client struct {
	baseURL string
	apiKey  string
	ttl     time.Duration
	http    *http.Client

	mu         sync.Mutex
	data       tables
	loaded     bool
	refreshing bool
	done       chan struct{}
	logged     map[string]string
	warned     map[string]bool
	fetchedAt  time.Time
	now        func() time.Time
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
		warned:  map[string]bool{},
		now:     time.Now,
	}
}

// Resolve answers the route for family; def fills any gap (no store, unknown
// family, empty model, a model that is missing or inactive in llm_models, a
// provider the family cannot drive). It never returns an error.
func (c *Client) Resolve(ctx context.Context, family string, def Route) Route {
	if c == nil || c.baseURL == "" {
		return def
	}
	if def.Provider == "" {
		def.Provider = InferProvider(def.Model)
	}
	got, ok := c.snapshot(ctx).routes[family]
	if !ok || strings.TrimSpace(got.Model) == "" {
		return def
	}
	got, ok = c.servable(family, got)
	if !ok {
		return def
	}
	c.noteChange(family, got)
	return got
}

func (c *Client) warnOnce(key, msg string, args ...any) {
	c.mu.Lock()
	seen := c.warned[key]
	c.warned[key] = true
	c.mu.Unlock()
	if !seen {
		slog.Error(msg, args...)
	}
}

func (c *Client) servable(family string, r Route) (Route, bool) {
	c.mu.Lock()
	data := c.data
	c.mu.Unlock()
	provider := ""
	if data.modelsLoaded {
		info, ok := data.models[r.Model]
		if !ok || !info.active {
			reason := "inactive"
			if !ok {
				reason = "missing from llm_models"
			}
			c.warnOnce("model|"+family+"|"+r.Model+"|"+reason,
				"LLM_ROUTE model unusable, using the compiled default",
				"family", family, "model", r.Model, "reason", reason)
			return r, false
		}
		provider = info.provider
	} else {
		provider = r.Provider
		if provider == "" {
			provider = InferProvider(r.Model)
		}
		c.warnOnce("inferred|"+r.Model, "LLM_ROUTE llm_models never loaded; provider inferred",
			"model", r.Model, "provider", provider)
	}
	if !OpenAICapableFamilies[family] && provider != ProviderGoogle {
		c.warnOnce("provider|"+family+"|"+r.Model,
			"LLM_ROUTE family can only drive Gemini; route refused, using the compiled default",
			"family", family, "model", r.Model, "provider", provider)
		return r, false
	}
	r.Provider = provider
	return r, true
}

// snapshot returns the cached tables. The first caller to find them stale
// starts one refresh, on a context detached from any caller (a canceled request
// must not poison the cache); other callers get the old copy while it runs, up
// to maxStale. With no copy yet, or one older than maxStale, callers wait for the
// refresh or their own context, whichever ends first.
func (c *Client) snapshot(ctx context.Context) tables {
	c.mu.Lock()
	if !c.fetchedAt.IsZero() && c.now().Sub(c.fetchedAt) < c.ttl {
		d := c.data
		c.mu.Unlock()
		return d
	}
	if !c.refreshing {
		c.refreshing = true
		c.done = make(chan struct{})
		go c.refresh(c.done)
	}
	done := c.done
	serveOld := c.loaded && c.now().Sub(c.fetchedAt) < maxStale
	d := c.data
	c.mu.Unlock()
	if serveOld {
		return d
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
	c.mu.Lock()
	d = c.data
	c.mu.Unlock()
	return d
}

func (c *Client) refresh(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*fetchTimeout)
	defer cancel()
	routes, err := c.fetch(ctx)
	var models map[string]modelInfo
	var merr error
	if err == nil {
		models, merr = c.fetchModels(ctx)
	}
	c.mu.Lock()
	// Stamp failures too so an outage costs one 2s fetch per TTL, not one per call.
	c.fetchedAt = c.now()
	if err == nil {
		c.data.routes = routes
		c.loaded = true
		// An empty table is not a table: it must not refuse every route.
		if merr == nil && len(models) > 0 {
			c.data.models, c.data.modelsLoaded = models, true
		}
	}
	c.refreshing = false
	c.mu.Unlock()
	close(done)
}

func (c *Client) noteChange(family string, r Route) {
	sig := fmt.Sprintf("%s|%s|%d|%g", r.Model, r.Provider, r.ThinkingBudget, r.DailyBudgetUSD)
	c.mu.Lock()
	prev, seen := c.logged[family]
	c.logged[family] = sig
	c.mu.Unlock()
	if !seen || prev != sig {
		slog.Info("LLM_ROUTE resolved", "family", family, "model", r.Model, "provider", r.Provider,
			"thinking_budget", r.ThinkingBudget, "daily_budget_usd", r.DailyBudgetUSD)
	}
}

func (c *Client) get(ctx context.Context, path, what string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, http.NoBody)
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
		return nil, fmt.Errorf("%s: status %d", what, resp.StatusCode)
	}
	return body, nil
}

func (c *Client) fetch(ctx context.Context) (map[string]Route, error) {
	body, err := c.get(ctx, routesPath, "llm-routes")
	if err != nil {
		return nil, err
	}
	return decodeRoutes(body)
}

func (c *Client) fetchModels(ctx context.Context) (map[string]modelInfo, error) {
	body, err := c.get(ctx, modelsPath, "llm-models")
	if err != nil {
		return nil, err
	}
	return decodeModels(body)
}

func decodeModels(body []byte) (map[string]modelInfo, error) {
	var env struct {
		Items []modelRow `json:"items"`
		Data  *struct {
			Items []modelRow `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	items := env.Items
	if env.Data != nil {
		items = env.Data.Items
	}
	out := make(map[string]modelInfo, len(items))
	for _, m := range items {
		if m.Model == "" || m.Provider == "" {
			continue
		}
		out[m.Model] = modelInfo{provider: m.Provider, active: m.Active == nil || *m.Active}
	}
	return out, nil
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
		route := Route{Model: r.Model, ThinkingBudget: r.ThinkingBudget, Provider: r.Provider}
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
