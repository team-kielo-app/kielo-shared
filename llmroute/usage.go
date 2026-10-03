package llmroute

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	usagePath       = "/internal/api/v3/localization/llm-usage"
	reservoirSize   = 512
	defaultFlushGap = 5 * time.Minute
	flushTimeout    = 3 * time.Second
)

// Sample is one finished model call.
type Sample struct {
	Family         string
	Model          string
	InputTokens    int64
	OutputTokens   int64
	ThinkingTokens int64
	USD            float64
	Latency        time.Duration
	Error          bool
	Retries        int64
}

type usageKey struct {
	hour                   time.Time
	service, family, model string
}

type usageAgg struct {
	calls, in, out, thinking, errors, retries int64
	usd                                       float64
	lat                                       []int
	seen                                      int64
}

// UsageRow is the wire shape of one rollup row (matches localization.llm_usage_hourly).
type UsageRow struct {
	Hour           time.Time `json:"hour"`
	Service        string    `json:"service"`
	Family         string    `json:"family"`
	Model          string    `json:"model"`
	Calls          int64     `json:"calls"`
	InputTokens    int64     `json:"input_tokens"`
	OutputTokens   int64     `json:"output_tokens"`
	ThinkingTokens int64     `json:"thinking_tokens"`
	USD            float64   `json:"usd"`
	Errors         int64     `json:"errors"`
	Retries        int64     `json:"retries"`
	LatencyMsP50   *int      `json:"latency_ms_p50"`
	LatencyMsP95   *int      `json:"latency_ms_p95"`
}

// Recorder aggregates samples in-process per (hour, service, family, model) and
// flushes them to kielo-localization. It never blocks or fails a model call.
type Recorder struct {
	service string
	on      bool
	url     string
	apiKey  string
	http    *http.Client
	now     func() time.Time

	mu   sync.Mutex
	aggs map[usageKey]*usageAgg
	rng  uint64
}

// NewRecorder builds a recorder posting to baseURL. Empty baseURL makes Record a no-op.
func NewRecorder(service, baseURL, internalAPIKey string) *Recorder {
	return &Recorder{
		service: service,
		on:      strings.TrimSpace(baseURL) != "",
		url:     strings.TrimSuffix(strings.TrimSpace(baseURL), "/") + usagePath,
		apiKey:  internalAPIKey,
		http:    &http.Client{Timeout: flushTimeout},
		now:     time.Now,
		aggs:    map[usageKey]*usageAgg{},
		rng:     88172645463325252,
	}
}

func (r *Recorder) enabled() bool { return r != nil && r.on }

// Record adds one call. Latency percentiles come from a bounded reservoir.
func (r *Recorder) Record(s Sample) {
	if !r.enabled() || s.Family == "" {
		return
	}
	k := usageKey{hour: r.now().UTC().Truncate(time.Hour), service: r.service, family: s.Family, model: s.Model}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.aggs[k]
	if a == nil {
		a = &usageAgg{}
		r.aggs[k] = a
	}
	a.calls++
	a.in += s.InputTokens
	a.out += s.OutputTokens
	a.thinking += s.ThinkingTokens
	a.usd += s.USD
	a.retries += s.Retries
	if s.Error {
		a.errors++
	}
	ms := int(s.Latency.Milliseconds())
	a.seen++
	if len(a.lat) < reservoirSize {
		a.lat = append(a.lat, ms)
	} else if j := r.next() % uint64(a.seen); j < reservoirSize {
		a.lat[j] = ms
	}
}

func (r *Recorder) next() uint64 {
	r.rng ^= r.rng << 13
	r.rng ^= r.rng >> 7
	r.rng ^= r.rng << 17
	return r.rng
}

func percentile(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted))+0.5) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// Drain returns and clears the accumulated rows.
func (r *Recorder) Drain() []UsageRow {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	aggs := r.aggs
	r.aggs = map[usageKey]*usageAgg{}
	r.mu.Unlock()
	rows := make([]UsageRow, 0, len(aggs))
	for k, a := range aggs {
		sort.Ints(a.lat)
		p50, p95 := percentile(a.lat, 0.50), percentile(a.lat, 0.95)
		rows = append(rows, UsageRow{
			Hour: k.hour, Service: k.service, Family: k.family, Model: k.model, Calls: a.calls,
			InputTokens: a.in, OutputTokens: a.out, ThinkingTokens: a.thinking, USD: a.usd,
			Errors: a.errors, Retries: a.retries, LatencyMsP50: &p50, LatencyMsP95: &p95,
		})
	}
	return rows
}

// Flush posts the accumulated rows. On failure the rows are put back for the next flush.
func (r *Recorder) Flush(ctx context.Context) error {
	rows := r.Drain()
	if len(rows) == 0 {
		return nil
	}
	if err := r.post(ctx, rows); err != nil {
		r.restore(rows)
		return err
	}
	return nil
}

func (r *Recorder) post(ctx context.Context, rows []UsageRow) error {
	body, err := json.Marshal(map[string]any{"rows": rows})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.apiKey != "" {
		req.Header.Set("X-Internal-API-Key", r.apiKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return &statusError{code: resp.StatusCode}
	}
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "llm-usage: status " + http.StatusText(e.code) }

// restore merges rows that failed to post back into the live buckets (counters only).
func (r *Recorder) restore(rows []UsageRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range rows {
		k := usageKey{hour: u.Hour, service: u.Service, family: u.Family, model: u.Model}
		a := r.aggs[k]
		if a == nil {
			a = &usageAgg{}
			r.aggs[k] = a
		}
		a.calls += u.Calls
		a.in += u.InputTokens
		a.out += u.OutputTokens
		a.thinking += u.ThinkingTokens
		a.usd += u.USD
		a.errors += u.Errors
		a.retries += u.Retries
	}
}

// Run flushes every gap (default 5 min) until ctx ends, then once more.
func (r *Recorder) Run(ctx context.Context, gap time.Duration) {
	if !r.enabled() {
		return
	}
	if gap <= 0 {
		gap = defaultFlushGap
	}
	t := time.NewTicker(gap)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
			_ = r.Flush(fctx)
			cancel()
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil {
				slog.Warn("LLM_USAGE flush failed", "err", err)
			}
		}
	}
}

var (
	recorderMu sync.RWMutex
	recorder   *Recorder
)

// StartUsage installs the process-wide recorder for the Configure'd service and
// starts its flush loop; it stops when ctx ends.
func StartUsage(ctx context.Context, baseURL, internalAPIKey string, gap time.Duration) {
	rec := NewRecorder(Service(), baseURL, internalAPIKey)
	recorderMu.Lock()
	recorder = rec
	recorderMu.Unlock()
	go rec.Run(ctx, gap)
}

// Record adds one call to the process-wide recorder (no-op until StartUsage).
func Record(s Sample) {
	recorderMu.RLock()
	rec := recorder
	recorderMu.RUnlock()
	rec.Record(s)
}
