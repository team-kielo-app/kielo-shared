// Package llmroute is the client for the AI-models control plane
// (docs/architecture/ai-models-control-plane.md). kielo-localization stores one
// route per LLM task family (model, thinking budget, daily budget); every owner
// resolves its model through Resolve and keeps its compiled value as the default.
//
// Like opswitch, Resolve reads an in-process copy of the whole table that
// refreshes at most every TTL (default 30s). When the store cannot be reached the
// last good copy keeps answering; with no copy at all, or a nil / unconfigured
// client, the caller's compiled default is returned (fail-open).
//
// A route may carry a canary candidate (model, thinking budget, share). ResolveKeyed
// sends share percent of keys to the candidate (Route.Variant == VariantCandidate),
// the same key always to the same model. Recorder samples carry each call's
// outcome and whether the compiled default ran in place of a refused route, and
// RecordOutcome counts what a caller's own check accepted or rejected. Configure
// and AllowProviders tell localization which providers this service can drive.
package llmroute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Task family keys. One per row of localization.llm_routes.
const (
	FamilyJukaLive = "juka_live"
	// FamilyJukaLiveFailover names the model a live call fails over to (the
	// convo agent picks it when the live route's provider errors or is unusable).
	FamilyJukaLiveFailover  = "juka_live_failover"
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

	routesPath       = "/internal/api/v3/localization/llm-routes"
	modelsPath       = "/internal/api/v3/localization/llm-models"
	capabilitiesPath = "/internal/api/v3/localization/llm-capabilities"

	// VariantRoute is the family's own model; VariantCandidate the canary model.
	// An empty Variant means VariantRoute.
	VariantRoute     = "route"
	VariantCandidate = "candidate"

	ProviderGoogle    = "google"
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	fetchTimeout      = 2 * time.Second
	maxResponseLen    = 1 << 20
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
	// Variant is VariantCandidate when the canary candidate was picked, else
	// VariantRoute (empty on a compiled default).
	Variant string
	// Requested is the model the store asked for when it could not be served here
	// (missing, inactive, provider not drivable) and the compiled default came back
	// instead; empty otherwise. A call made with such a Route is a fallback.
	Requested string
}

// providerByPrefix is the last resort when llm_models has no row for a routed
// model: the model-name family decides.
var providerByPrefix = []struct{ prefix, provider string }{
	{"gemini-", ProviderGoogle},
	{"gpt-", ProviderOpenAI},
	{"claude-", ProviderAnthropic},
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
	// Candidate fields are decoded loosely: a malformed one drops that
	// candidate, never the route table.
	CandidateModel          string `json:"candidate_model"`
	CandidateThinkingBudget any    `json:"candidate_thinking_budget"`
	CandidateShare          any    `json:"candidate_share"`
}

// candidate is a route's canary: share percent of keys run model.
type candidate struct {
	model    string
	thinking int
	share    int
}

type routeTable struct {
	routes     map[string]Route
	candidates map[string]candidate
}

func wholeNumber(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

// OpenAICapableFamilies are the families whose call sites can drive an OpenAI
// model in a process that declares nothing (the convo agent's routed_llm and
// LiveKit builder). Every process can drive Gemini; one whose call sites can
// drive more declares it with AllowProviders. A route naming a provider the
// process cannot drive is refused and the caller's compiled default runs,
// logged once.
var OpenAICapableFamilies = map[string]bool{
	FamilyJukaLive:         true,
	FamilyJukaLiveFailover: true,
	FamilyJukaFeedback:     true,
	FamilyJukaStepCheck:    true,
}

// familySet is the families a provider can be driven for; all covers every family.
type familySet struct {
	all      bool
	families map[string]bool
}

var (
	drivableMu sync.RWMutex
	drivable   = map[string]familySet{ProviderOpenAI: {families: OpenAICapableFamilies}}
)

// AllowProviders declares that this process's call sites can drive the
// providers, for the given families or, with none, for every family. Call it at
// start-up.
func AllowProviders(providers []string, families ...string) {
	allowProviders(providers, families)
	queueCapabilityReport()
}

func allowProviders(providers, families []string) {
	drivableMu.Lock()
	defer drivableMu.Unlock()
	for _, p := range providers {
		current := drivable[p]
		if len(families) == 0 || current.all {
			drivable[p] = familySet{all: true}
			continue
		}
		next := map[string]bool{}
		for f := range current.families {
			next[f] = true
		}
		for _, f := range families {
			next[f] = true
		}
		drivable[p] = familySet{families: next}
	}
}

// CanDrive reports whether this process can drive the provider for the family.
func CanDrive(family, provider string) bool {
	if provider == ProviderGoogle {
		return true
	}
	drivableMu.RLock()
	defer drivableMu.RUnlock()
	set := drivable[provider]
	return set.all || set.families[family]
}

// maxStale bounds how long a stale copy keeps answering while a refresh runs;
// past it callers wait (up to their context) for the refresh.
const maxStale = 5 * time.Minute

type tables struct {
	routes       map[string]Route
	candidates   map[string]candidate
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
// provider the family cannot drive). While the family runs a canary, each call
// draws whether it gets the candidate; use ResolveKeyed to keep one unit on one
// model. It never returns an error.
func (c *Client) Resolve(ctx context.Context, family string, def Route) Route {
	return c.ResolveKeyed(ctx, family, def, "")
}

// ResolveKeyed is Resolve with a stable key (a deck, learner or item id): while
// the family runs a canary, crc32(family + ":" + key) % 100 < share picks the
// candidate, so a key always sees one model. An empty key draws per call.
func (c *Client) ResolveKeyed(ctx context.Context, family string, def Route, key string) Route {
	if c == nil || c.baseURL == "" {
		return def
	}
	if def.Provider == "" {
		def.Provider = InferProvider(def.Model)
	}
	data := c.snapshot(ctx)
	got, have := data.routes[family]
	have = have && strings.TrimSpace(got.Model) != ""
	served, ok, requested := Route{}, false, ""
	if have {
		if served, ok = c.servable(family, got); !ok {
			requested = got.Model
		}
	}
	if cand, share, picked := c.candidateRoute(family, data, got, have); picked && inShare(family, key, share) {
		return cand
	}
	if !ok {
		def.Requested = requested
		return def
	}
	served.Variant = VariantRoute
	c.noteChange(family, served)
	return served
}

// candidateRoute is the family's servable canary and its share; ok is false when
// there is none, it is the family's own model, or this process cannot drive it.
func (c *Client) candidateRoute(family string, data tables, base Route, haveBase bool) (route Route, share int, ok bool) {
	cand, found := data.candidates[family]
	if !found || cand.share <= 0 || (haveBase && base.Model == cand.model) {
		return Route{}, 0, false
	}
	served, ok := c.servable(family, Route{
		Model: cand.model, ThinkingBudget: cand.thinking, DailyBudgetUSD: base.DailyBudgetUSD, Variant: VariantCandidate,
	})
	if !ok {
		return Route{}, 0, false
	}
	c.noteCandidate(family, served, cand.share)
	return served, cand.share, true
}

// inShare reports whether key falls in a candidate's share percent.
func inShare(family, key string, share int) bool {
	if share <= 0 {
		return false
	}
	if key == "" {
		return rand.IntN(100) < share //nolint:gosec // a canary draw, not a security decision
	}
	return int(crc32.ChecksumIEEE([]byte(family+":"+key))%100) < share
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
	if !CanDrive(family, provider) {
		c.warnOnce("provider|"+family+"|"+r.Model,
			"LLM_ROUTE family cannot drive this provider here; route refused, using the compiled default",
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
	table, err := c.fetch(ctx)
	var models map[string]modelInfo
	var merr error
	if err == nil {
		models, merr = c.fetchModels(ctx)
	}
	c.mu.Lock()
	// Stamp failures too so an outage costs one 2s fetch per TTL, not one per call.
	c.fetchedAt = c.now()
	if err == nil {
		c.data.routes, c.data.candidates = table.routes, table.candidates
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

func (c *Client) noteCandidate(family string, r Route, share int) {
	sig := fmt.Sprintf("%s|%s|%d|%d", r.Model, r.Provider, r.ThinkingBudget, share)
	c.mu.Lock()
	prev, seen := c.logged["candidate|"+family]
	c.logged["candidate|"+family] = sig
	c.mu.Unlock()
	if !seen || prev != sig {
		slog.Info("LLM_ROUTE candidate", "family", family, "model", r.Model, "provider", r.Provider,
			"thinking_budget", r.ThinkingBudget, "share", share)
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

func (c *Client) fetch(ctx context.Context) (routeTable, error) {
	body, err := c.get(ctx, routesPath, "llm-routes")
	if err != nil {
		return routeTable{}, err
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

func decodeRoutes(body []byte) (routeTable, error) {
	var env struct {
		Items []row `json:"items"`
		Data  *struct {
			Items []row `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return routeTable{}, err
	}
	items := env.Items
	if env.Data != nil {
		items = env.Data.Items
	}
	out := routeTable{routes: make(map[string]Route, len(items)), candidates: map[string]candidate{}}
	for _, r := range items {
		route := Route{Model: r.Model, ThinkingBudget: r.ThinkingBudget, Provider: r.Provider}
		if r.DailyBudgetUSD != nil {
			route.DailyBudgetUSD = *r.DailyBudgetUSD
		}
		out.routes[r.Family] = route
		if cand, ok := r.candidate(); ok {
			out.candidates[r.Family] = cand
		}
	}
	return out, nil
}

func (r row) candidate() (candidate, bool) {
	model := strings.TrimSpace(r.CandidateModel)
	share, ok := wholeNumber(r.CandidateShare)
	if model == "" || !ok || share <= 0 {
		return candidate{}, false
	}
	thinking := ThinkingDefault
	if r.CandidateThinkingBudget != nil {
		if t, ok := wholeNumber(r.CandidateThinkingBudget); ok {
			thinking = t
		} else {
			return candidate{}, false
		}
	}
	return candidate{model: model, thinking: thinking, share: min(share, 100)}, true
}

var (
	defaultMu     sync.RWMutex
	defaultClient *Client
	defaultSvc    string
)

// Configure installs the process-wide client and service name used by Resolve
// and the usage recorder, then reports what this service can drive (a background
// goroutine, best effort). Empty baseURL leaves every family on its default.
func Configure(service, baseURL, internalAPIKey string) {
	defaultMu.Lock()
	defaultClient = NewClient(baseURL, internalAPIKey, DefaultTTL)
	defaultSvc = service
	defaultMu.Unlock()
	queueCapabilityReport()
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
	return ResolveKeyed(ctx, family, def, "")
}

// ResolveKeyed is Resolve with a stable key for canary selection (see Client.ResolveKeyed).
func ResolveKeyed(ctx context.Context, family string, def Route, key string) Route {
	defaultMu.RLock()
	c := defaultClient
	defaultMu.RUnlock()
	return c.ResolveKeyed(ctx, family, def, key)
}

// Model is Resolve(...).Model with the compiled default for the model name.
func Model(ctx context.Context, family, defaultModel string) string {
	return Resolve(ctx, family, Route{Model: defaultModel, ThinkingBudget: ThinkingDefault}).Model
}

type capabilityProvider struct {
	Provider string   `json:"provider"`
	Families []string `json:"families"`
}

type capabilityReport struct {
	Service   string               `json:"service"`
	Providers []capabilityProvider `json:"providers"`
}

// capabilities is the body of POST llm-capabilities: google always (every
// family), plus every provider this process declared (nil families = every family).
func capabilities(service string) capabilityReport {
	drivableMu.RLock()
	defer drivableMu.RUnlock()
	providers := []capabilityProvider{{Provider: ProviderGoogle}}
	names := make([]string, 0, len(drivable))
	for name := range drivable {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set := drivable[name]
		if name == ProviderGoogle || (!set.all && len(set.families) == 0) {
			continue
		}
		p := capabilityProvider{Provider: name}
		if !set.all {
			p.Families = make([]string, 0, len(set.families))
			for f := range set.families {
				p.Families = append(p.Families, f)
			}
			sort.Strings(p.Families)
		}
		providers = append(providers, p)
	}
	return capabilityReport{Service: service, Providers: providers}
}

// ReportCapabilities posts what this service can drive to kielo-localization.
func (c *Client) ReportCapabilities(ctx context.Context, service string) error {
	if c == nil || c.baseURL == "" || service == "" {
		return nil
	}
	body, err := json.Marshal(capabilities(service))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+capabilitiesPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseLen))
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("llm-capabilities: status %d", resp.StatusCode)
	}
	return nil
}

var (
	capabilityDelay = time.Second
	capabilityMu    sync.Mutex
	capabilityDirty bool
	capabilityBusy  bool
)

// queueCapabilityReport asks for a capability report; calls close together
// (Configure, then AllowProviders at start-up) share one post, made after a short
// delay on a goroutine. Fire and forget: a failure is only logged.
func queueCapabilityReport() {
	defaultMu.RLock()
	c, service := defaultClient, defaultSvc
	defaultMu.RUnlock()
	if c == nil || c.baseURL == "" || service == "" {
		return
	}
	capabilityMu.Lock()
	capabilityDirty = true
	if capabilityBusy {
		capabilityMu.Unlock()
		return
	}
	capabilityBusy = true
	capabilityMu.Unlock()
	go reportCapabilities()
}

func reportCapabilities() {
	for {
		capabilityMu.Lock()
		delay := capabilityDelay
		capabilityMu.Unlock()
		time.Sleep(delay)
		capabilityMu.Lock()
		if !capabilityDirty {
			capabilityBusy = false
			capabilityMu.Unlock()
			return
		}
		capabilityDirty = false
		capabilityMu.Unlock()
		defaultMu.RLock()
		c, service := defaultClient, defaultSvc
		defaultMu.RUnlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*fetchTimeout)
		if err := c.ReportCapabilities(ctx, service); err != nil {
			slog.Warn("LLM_CAPABILITIES report failed", "err", err)
		}
		cancel()
	}
}
