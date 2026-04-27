// Package serverctl provides app-lifecycle helpers shared across the
// Kielo Echo HTTP services — currently a graceful-shutdown helper that
// blocks on SIGINT/SIGTERM and tears the server + caller-supplied
// resources down with a deadline.
package serverctl

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Shutdowner is anything that can be gracefully shut down with a
// context deadline — both *echo.Echo and *http.Server satisfy this.
// Defining the interface lets WaitForShutdown serve raw-net/http
// services (kielo-convo orchestrator) and Echo services (everything
// else) from one helper.
type Shutdowner interface {
	Shutdown(ctx context.Context) error
}

// DefaultShutdownTimeout is the deadline for Shutdown when the caller
// doesn't pass an explicit timeout. 10s matches Cloud Run's default
// SIGTERM-to-SIGKILL grace window — we want to drain in-flight
// requests but not hold the instance hostage.
const DefaultShutdownTimeout = 10 * time.Second

// WaitForShutdown blocks until SIGINT or SIGTERM, then runs the
// supplied cleanup callbacks (in registration order) and finally calls
// Echo's Shutdown with a bounded ctx.
//
// Cleanups run *before* Echo.Shutdown so background context-cancel
// signals propagate to in-flight handlers — those handlers can then
// stop fast and Echo.Shutdown closes the listener once they unwind.
// Caller-managed resources that must outlast handler cleanup (DB pools,
// Redis clients) should be closed *after* WaitForShutdown returns.
//
// timeout=0 uses DefaultShutdownTimeout. A negative value disables the
// deadline (Echo.Shutdown gets context.Background()).
//
// Replaces the verbatim `signal.Notify(quit, os.Interrupt, syscall.SIGTERM)`
// + `<-quit` + `e.Shutdown(...)` block that lived in every Kielo
// service's main.go (with subtly different timeouts and cleanup
// ordering). Centralizes the pattern so production reliability fixes
// apply everywhere.
func WaitForShutdown(s Shutdowner, timeout time.Duration, cleanups ...func()) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	shutdownOnSignal(s, quit, timeout, cleanups)
}

// shutdownOnSignal is the testable core of WaitForShutdown. It takes a
// pre-built signal channel so tests can fire a synthetic value without
// raising real OS signals (which would terminate the test process).
func shutdownOnSignal(s Shutdowner, sig <-chan os.Signal, timeout time.Duration, cleanups []func()) {
	received := <-sig
	log.Printf("Shutting down server (signal=%s)...", received)

	for _, cleanup := range cleanups {
		if cleanup == nil {
			continue
		}
		cleanup()
	}

	ctx := context.Background()
	if timeout >= 0 {
		t := timeout
		if t == 0 {
			t = DefaultShutdownTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}

	if err := s.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}
}
