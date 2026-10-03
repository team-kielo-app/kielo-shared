// Package opswitch is the client for operator kill switches
// (docs/architecture/kill-switches.md). An admin turns a feature off live in
// the admin UI; kielo-localization stores the switch and every feature owner
// checks it once at its entry point through this package.
//
// Checks read an in-process copy of the whole switch table that refreshes at
// most every TTL (default 30s). When the store cannot be reached the last good
// copy keeps answering; with no copy at all every switch reads as on
// (fail-open). A Client that is nil, or built with an empty base URL, also
// reads as on, so a service without LOCALIZATION_SERVICE_URL is unaffected.
package opswitch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	KeyConvoCalls        = "convo.calls"
	KeyDictionaryMinting = "content.dictionary_minting"
	KeyLLMGeneration     = "engine.llm_generation"
	KeyKTVFeed           = "ktv.feed"
	KeyPushCampaigns     = "comms.push_campaigns"
	KeyWebIngest         = "ingest.web"

	ScopeGlobal   = "global"
	ScopeLanguage = "language"
	ScopePlatform = "platform"

	// DefaultTTL bounds how stale a flip can be on any one instance.
	DefaultTTL = 30 * time.Second
	// HeaderPlatform carries the client platform (ios, android, web).
	HeaderPlatform = "X-Kielo-Platform"
	// DefaultMessage is shown when the operator wrote no message.
	DefaultMessage = "This is paused for a moment. Please try again soon."

	switchesPath   = "/internal/api/v3/localization/operator-switches"
	fetchTimeout   = 2 * time.Second
	maxResponseLen = 1 << 20
)

// Row is one stored switch row.
type Row struct {
	SwitchKey  string  `json:"switch_key"`
	ScopeType  string  `json:"scope_type"`
	ScopeValue string  `json:"scope_value"`
	Enabled    bool    `json:"enabled"`
	Message    *string `json:"message,omitempty"`
}

// Scope is what a request is: its learning language and client platform.
type Scope struct {
	Language string
	Platform string
}

// Decision is the answer for one key and scope.
type Decision struct {
	Off        bool
	Message    string
	Custom     bool
	ScopeType  string
	ScopeValue string
}

// Evaluate is the pure rule: the switch is off when any row matching the scope
// (global, the language, the platform) is disabled. The most specific off row
// supplies the message: language, then platform, then global.
func Evaluate(rows []Row, key string, scope Scope) Decision {
	lang := strings.ToLower(strings.TrimSpace(scope.Language))
	platform := strings.ToLower(strings.TrimSpace(scope.Platform))
	best := -1
	var chosen Row
	for _, r := range rows {
		if r.SwitchKey != key || r.Enabled {
			continue
		}
		rank := -1
		switch {
		case r.ScopeType == ScopeLanguage && lang != "" && r.ScopeValue == lang:
			rank = 2
		case r.ScopeType == ScopePlatform && platform != "" && r.ScopeValue == platform:
			rank = 1
		case r.ScopeType == ScopeGlobal:
			rank = 0
		}
		if rank > best {
			best, chosen = rank, r
		}
	}
	if best < 0 {
		return Decision{}
	}
	d := Decision{Off: true, Message: DefaultMessage, ScopeType: chosen.ScopeType, ScopeValue: chosen.ScopeValue}
	if chosen.Message != nil && strings.TrimSpace(*chosen.Message) != "" {
		d.Message, d.Custom = strings.TrimSpace(*chosen.Message), true
	}
	return d
}

// Client reads the switch table and caches it.
type Client struct {
	baseURL string
	apiKey  string
	ttl     time.Duration
	http    *http.Client

	mu        sync.Mutex
	rows      []Row
	loaded    bool
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
		now:     time.Now,
	}
}

// Check answers whether key is off for scope. It never returns an error: a
// store failure keeps the last good copy, or reads as on.
func (c *Client) Check(ctx context.Context, key string, scope Scope) Decision {
	if c == nil || c.baseURL == "" {
		return Decision{}
	}
	return Evaluate(c.snapshot(ctx), key, scope)
}

func (c *Client) snapshot(ctx context.Context) []Row {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetchedAt.IsZero() && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.rows
	}
	rows, err := c.fetch(ctx)
	// Stamp failures too so an outage costs one 2s fetch per TTL, not one per request.
	c.fetchedAt = c.now()
	if err == nil {
		c.rows, c.loaded = rows, true
	}
	return c.rows
}

func (c *Client) fetch(ctx context.Context) ([]Row, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+switchesPath, http.NoBody)
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
		return nil, fmt.Errorf("operator-switches: status %d", resp.StatusCode)
	}
	return decodeRows(body)
}

func decodeRows(body []byte) ([]Row, error) {
	var env struct {
		Items []Row `json:"items"`
		Data  *struct {
			Items []Row `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.Data != nil {
		return env.Data.Items, nil
	}
	return env.Items, nil
}
