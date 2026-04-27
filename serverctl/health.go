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
func Readiness(db Pinger) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), readinessPingTimeout)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			return c.String(http.StatusServiceUnavailable, "Database connection failed")
		}
		return c.String(http.StatusOK, "OK")
	}
}
