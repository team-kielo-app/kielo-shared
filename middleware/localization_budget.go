// Package middleware: LocalizationBudget (Sweep TTTT-I) attaches a
// per-request localization counter to ctx + stamps the totals as
// response headers when the handler returns. Wire-up: register on
// every service group that exposes localized payloads (the standard
// `/api/v3/*` + `/internal/*` chains).
//
// Visible headers:
//   X-Kielo-Loc-Refs       — total ref count resolved
//   X-Kielo-Loc-Overrides  — override-store lookups (composite SQL count)
//   X-Kielo-Loc-CacheGets  — Redis MGET / GET round-trips
//   X-Kielo-Loc-Providers  — LLM / opus-mt provider calls
//
// Pre-TTTT-B the GET /concept-hubs/by-concept endpoint emitted
// `X-Kielo-Loc-Overrides: 264` (one per scenario); post-TTTT-B it's
// `X-Kielo-Loc-Overrides: 1`. Dashboards diff these over time to
// detect new N+1 regressions.

package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/localization"
)

const (
	HeaderKieloLocRefs      = "X-Kielo-Loc-Refs"
	HeaderKieloLocOverrides = "X-Kielo-Loc-Overrides"
	HeaderKieloLocCacheGets = "X-Kielo-Loc-Cachegets"
	HeaderKieloLocProviders = "X-Kielo-Loc-Providers"
)

// LocalizationBudget returns Echo middleware that:
//  1. Attaches a fresh localization budget counter to the request ctx
//     via localization.WithBudget.
//  2. After the handler completes, stamps the totals as response headers.
//
// No-op for handlers that don't invoke the seam — the counter just
// remains at zero. Safe to register globally.
func LocalizationBudget() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			ctx := localization.WithBudget(req.Context())
			c.SetRequest(req.WithContext(ctx))
			err := next(c)
			stampBudgetHeaders(c.Response().Header(), ctx)
			return err
		}
	}
}

// LocalizationBudgetStdlib is the chi/net-http variant of
// LocalizationBudget for services that don't use Echo (kielo-convo's
// go_orchestrator uses chi). Same contract: stamps the budget
// snapshot as response headers after the wrapped handler returns.
//
// Header stamping is best-effort: chi handlers that call WriteHeader
// before returning will skip the post-handler stamp; the wrapper
// emits the headers eagerly via budgetResponseWriter so they land
// in either flow.
func LocalizationBudgetStdlib(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := localization.WithBudget(r.Context())
		r = r.WithContext(ctx)
		bw := &budgetResponseWriter{ResponseWriter: w, ctx: ctx}
		next.ServeHTTP(bw, r)
		// Final flush in case the handler never wrote headers
		// (e.g. 204 No Content path with no body).
		bw.flush()
	})
}

// stampBudgetHeaders writes the four loc-budget headers onto h.
// Idempotent — safe to call from both the Echo and stdlib middleware.
func stampBudgetHeaders(h http.Header, ctx context.Context) {
	snap := localization.BudgetSnapshotFromContext(ctx)
	h.Set(HeaderKieloLocRefs, strconv.Itoa(snap.RefsResolved))
	h.Set(HeaderKieloLocOverrides, strconv.Itoa(snap.OverrideLookups))
	h.Set(HeaderKieloLocCacheGets, strconv.Itoa(snap.CacheGets))
	h.Set(HeaderKieloLocProviders, strconv.Itoa(snap.ProviderCalls))
}

// budgetResponseWriter intercepts WriteHeader so we stamp the budget
// just before the status line goes out. Mirrors the standard chi
// pattern of wrapping w to hook the status-emission point.
type budgetResponseWriter struct {
	http.ResponseWriter
	ctx     context.Context
	stamped bool
}

func (b *budgetResponseWriter) WriteHeader(code int) {
	b.flush()
	b.ResponseWriter.WriteHeader(code)
}

func (b *budgetResponseWriter) Write(p []byte) (int, error) {
	b.flush()
	return b.ResponseWriter.Write(p)
}

func (b *budgetResponseWriter) flush() {
	if b.stamped {
		return
	}
	b.stamped = true
	stampBudgetHeaders(b.ResponseWriter.Header(), b.ctx)
}
