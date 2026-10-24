package pgxcount

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	shareddb "github.com/team-kielo-app/kielo-shared/db"
)

// TestPool opens a pool on DATABASE_URL whose connections carry a Tracer with
// the given per-round-trip delay, or skips the test when DATABASE_URL is unset.
func TestPool(t testing.TB, delay time.Duration) (*pgxpool.Pool, *Tracer) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL environment variable is required")
	}
	cfg, err := shareddb.TestPoolConfig(dsn)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	tracer := NewTracer(delay)
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, tracer
}

var (
	budgetMu   sync.RWMutex
	budgetData []byte
)

// RegisterBudgets sets the budget file the package's Budget reads. A service
// embeds its round_trip_budgets.yaml in a _test.go file (go:embed) and calls
// this from an init there, so no production code depends on this package.
func RegisterBudgets(yaml []byte) {
	budgetMu.Lock()
	defer budgetMu.Unlock()
	budgetData = yaml
}

// Budget is the round-trip ceiling recorded for key in the registered
// round_trip_budgets.yaml, a flat file of `key: count` lines with # comments.
func Budget(t testing.TB, key string) int64 {
	t.Helper()
	budgetMu.RLock()
	data := budgetData
	budgetMu.RUnlock()
	if data == nil {
		t.Fatalf("pgxcount: no budget file registered; embed round_trip_budgets.yaml and call RegisterBudgets")
	}
	n, ok := parseBudgets(data)[key]
	if !ok {
		t.Fatalf("pgxcount: no round-trip budget for %q in round_trip_budgets.yaml", key)
	}
	return n
}

func parseBudgets(data []byte) map[string]int64 {
	out := map[string]int64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		out[strings.Trim(strings.TrimSpace(k), `"'`)] = n
	}
	return out
}
