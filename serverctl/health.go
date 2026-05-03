package serverctl

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// readinessPingTimeout caps the database ping inside a Readiness probe
// so a misbehaving database backend can't tie up the probe goroutine
// past the orchestrator's timeout window. 2s matches Kubernetes /
// Cloud Run defaults — short enough that a stuck probe gets retried
// quickly, long enough to absorb network jitter.
const readinessPingTimeout = 2 * time.Second

// Pinger is the minimum surface a Readiness handler needs from a
// database pool. Implemented by *pgxpool.Pool. Defining the interface
// here keeps kielo-shared/serverctl free of a direct pgxpool dependency
// (the package is already used for raw http.Server lifecycle code that
// wouldn't otherwise need pgx) and lets tests pass a fake pinger.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Liveness returns an Echo handler that always returns 200 OK with the
// body "OK". Wire this on /health (or /livez) for orchestrator liveness
// probes — failing this restarts the container, so the handler must
// never block, query a database, or fail. Replaces the verbatim
// `c.String(200, "OK")` closure that appears inline in every Kielo
// service's main.go.
func Liveness() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}
}

// Readiness returns an Echo handler that pings the supplied database
// and returns 503 Service Unavailable when the ping fails, 200 OK
// otherwise. Wire on /readyz (separate from /health) for orchestrator
// readiness probes — failing this removes the instance from the
// load balancer's rotation but does NOT restart the container, which
// is what we want during transient database hiccups.
//
// The ping ctx is bounded by readinessPingTimeout so a stuck pgx pool
// can't outlive the orchestrator's probe window.
//
// For services with more than just a database (Redis, Pub/Sub,
// upstream HTTP services), use ReadinessWithChecks instead.
func Readiness(db Pinger) echo.HandlerFunc {
	return ReadinessWithChecks([]ReadinessCheck{
		{Name: "database", Check: func(ctx context.Context) error { return db.Ping(ctx) }},
	})
}

// ReadinessCheck is one named dependency probe. Run inside a 2s
// timeout context; any non-nil error fails the readiness check and
// surfaces in the JSON response body so the operator running
// `curl /readyz` can immediately see which dep is sick.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// readinessReport is the JSON body returned by ReadinessWithChecks.
// Aggregated `status` is "ready" only when every individual check
// passes; otherwise "not_ready" with each failed dep's error.
type readinessReport struct {
	Status string                  `json:"status"`
	Checks map[string]readinessDep `json:"checks"`
}

type readinessDep struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ReadinessWithChecks returns an Echo handler that runs every supplied
// dep check in parallel under a shared 2s deadline. Returns 200 with
// `{"status":"ready", "checks": {...}}` when ALL checks pass, otherwise
// 503 with the same shape but `status:"not_ready"` and the error
// message on each failed dep.
//
// Use this on /readyz for services with multiple deps (Pub/Sub +
// Redis + upstream HTTP). Cloud Run's readiness probe sees the 5xx
// status code and pulls the instance out of the load balancer rotation
// without killing the container — exactly what we want during a
// transient downstream outage. Liveness (/health) keeps returning 200
// so the container itself isn't restarted.
//
// Empty checks slice is valid and always returns 200 — equivalent to
// Liveness, but distinct semantically.
func ReadinessWithChecks(checks []ReadinessCheck) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), readinessPingTimeout)
		defer cancel()

		report := readinessReport{
			Status: "ready",
			Checks: make(map[string]readinessDep, len(checks)),
		}
		// Run checks in parallel — one slow dep shouldn't serialize the
		// whole probe. Bounded by the shared ctx deadline.
		type result struct {
			name string
			err  error
		}
		results := make(chan result, len(checks))
		for _, ch := range checks {
			go func() {
				results <- result{name: ch.Name, err: ch.Check(ctx)}
			}()
		}
		anyFailed := false
		for range checks {
			r := <-results
			dep := readinessDep{OK: r.err == nil}
			if r.err != nil {
				dep.Error = r.err.Error()
				anyFailed = true
			}
			report.Checks[r.name] = dep
		}
		if anyFailed {
			report.Status = "not_ready"
			return c.JSON(http.StatusServiceUnavailable, report)
		}
		return c.JSON(http.StatusOK, report)
	}
}
