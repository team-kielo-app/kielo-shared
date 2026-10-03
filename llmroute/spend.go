package llmroute

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrFamilyBudgetExceeded is returned when a family has spent its daily budget in this process.
var ErrFamilyBudgetExceeded = errors.New("llm family daily budget reached")

// price is USD per million tokens (input, output including thinking).
type price struct{ in, out float64 }

// prices mirrors localization.llm_models and the Python llm_usage table. An
// unlisted model books at the dearest listed rate, never $0.
var prices = map[string]price{
	"gemini-3.8-flash":      {0.75, 3.75},
	"gemini-3.5-flash":      {1.50, 9.00},
	"gemini-3.1-flash-lite": {0.25, 1.50},
	"gemini-3.5-flash-lite": {0.30, 2.50},
	"gemini-2.5-flash":      {0.30, 2.50},
	"gemini-2.5-flash-lite": {0.10, 0.40},
	"gemini-2.5-pro":        {1.25, 10.00},
	"gpt-4o":                {2.50, 10.00},
	"gpt-4o-mini":           {0.15, 0.60},
}

var fallbackPrice = price{2.50, 10.00}

// EstimateUSD prices one call; thinking tokens bill as output.
func EstimateUSD(model string, in, out, thinking int64) float64 {
	p, ok := prices[model]
	if !ok {
		p = fallbackPrice
	}
	return (float64(in)*p.in + float64(out+thinking)*p.out) / 1e6
}

// Spend books per-family USD for the current UTC day in this process. The Go
// services share no counter store, so the per-family cap is per process, like
// the seam's hourly call cap.
type Spend struct {
	mu  sync.Mutex
	day time.Time
	usd map[string]float64
	now func() time.Time
}

// NewSpend returns an empty ledger.
func NewSpend() *Spend { return &Spend{usd: map[string]float64{}, now: time.Now} }

var defaultSpend = NewSpend()

func (s *Spend) roll() {
	day := s.now().UTC().Truncate(24 * time.Hour)
	if !day.Equal(s.day) {
		s.day, s.usd = day, map[string]float64{}
	}
}

// Admit refuses the call when family has already spent budget (0 = no cap).
func (s *Spend) Admit(family string, budget float64) error {
	if budget <= 0 || family == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roll()
	if spent := s.usd[family]; spent >= budget {
		return fmt.Errorf("%w: family=%s spent=$%.4f budget=$%.4f", ErrFamilyBudgetExceeded, family, spent, budget)
	}
	return nil
}

// Book adds usd to family's day total.
func (s *Spend) Book(family string, usd float64) {
	if family == "" || usd <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roll()
	s.usd[family] += usd
}

// Spent is family's booked USD today.
func (s *Spend) Spent(family string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roll()
	return s.usd[family]
}

// Admit checks the process-wide ledger against budget.
func Admit(family string, budget float64) error { return defaultSpend.Admit(family, budget) }

// Book books usd on the process-wide ledger.
func Book(family string, usd float64) { defaultSpend.Book(family, usd) }

// ResetSpend clears the process-wide ledger (test hook).
func ResetSpend() { defaultSpend = NewSpend() }
