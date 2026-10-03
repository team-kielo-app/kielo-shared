package llm

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrPaidCallRefused is returned (wrapped in *Error, class client_error) when
// the paid-LLM guard refuses a call. It is deterministic: never retry it.
var ErrPaidCallRefused = errors.New("paid LLM call refused")

const (
	envAllowPaidCalls   = "LLM_ALLOW_PAID_CALLS"
	envHourlyCallCap    = "LLM_HOURLY_CALL_CAP"
	defaultHourlyCap    = 200
	geminiPaidHostMatch = "generativelanguage.googleapis.com"
)

var (
	guardMu     sync.Mutex
	guardWindow time.Time
	guardCalls  int
	guardNow    = time.Now
)

// isProductionEnv mirrors kielo_shared.llm.spend_guard.is_production.
func isProductionEnv() bool {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	if name != "" {
		return name == "production" || name == "prod"
	}
	return os.Getenv("K_SERVICE") != ""
}

// admitPaidCall refuses a paid call outside production unless
// LLM_ALLOW_PAID_CALLS=true, and caps calls per clock hour in-process
// (LLM_HOURLY_CALL_CAP; default 200 outside production, off in production).
// The Python guard additionally keeps a Redis-backed rolling USD budget; the Go
// side has no shared counter, so its cap is per process.
func admitPaidCall(task, provider string) error {
	prod := isProductionEnv()
	if !prod && !strings.EqualFold(strings.TrimSpace(os.Getenv(envAllowPaidCalls)), "true") {
		return refused("paid LLM calls are disabled outside production; set LLM_ALLOW_PAID_CALLS=true to allow", task, provider)
	}
	capPerHour := defaultHourlyCap
	if prod {
		capPerHour = 0
	}
	if raw := strings.TrimSpace(os.Getenv(envHourlyCallCap)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			capPerHour = v
		}
	}
	if capPerHour <= 0 {
		return nil
	}
	guardMu.Lock()
	defer guardMu.Unlock()
	hour := guardNow().Truncate(time.Hour)
	if !hour.Equal(guardWindow) {
		guardWindow, guardCalls = hour, 0
	}
	guardCalls++
	if guardCalls > capPerHour {
		return refused(fmt.Sprintf("hourly LLM call cap reached (%d/h)", capPerHour), task, provider)
	}
	return nil
}

func refused(msg, task, provider string) error {
	err := fmt.Errorf("%w: %s (task=%s provider=%s)", ErrPaidCallRefused, msg, task, provider)
	fmt.Fprintf(os.Stderr, "LLM_GUARD_REFUSED reason=%q task=%s provider=%s\n", msg, task, provider)
	return &Error{Class: ErrorClassClientError, Err: err}
}
