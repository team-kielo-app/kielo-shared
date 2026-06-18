package serverctl

import (
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// startEchoForTest spawns an Echo server on an ephemeral port and
// returns once it has bound the listener. The returned function blocks
// until Start unwinds (which happens when shutdownOnSignal calls
// Shutdown) — callers should call it after the shutdown completes.
func startEchoForTest(t *testing.T) (server *echo.Echo, waitForExit func()) {
	t.Helper()
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.GET("/ping", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	var startErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		startErr = e.Start("127.0.0.1:0")
	}()

	// Echo has no "ready" signal; 50ms is the standard wait used in
	// httptest patterns. Tests that flake here would indicate a
	// dramatically slower CI host — bump if seen in practice.
	time.Sleep(50 * time.Millisecond)

	return e, func() {
		wg.Wait()
		if startErr != nil && !errors.Is(startErr, http.ErrServerClosed) {
			t.Fatalf("e.Start returned unexpected error: %v", startErr)
		}
	}
}

func TestShutdownOnSignal_RunsCleanupsInOrder(t *testing.T) {
	e, waitStart := startEchoForTest(t)

	var cleanupOrder []int
	var mu sync.Mutex
	cleanups := []func(){
		func() { mu.Lock(); cleanupOrder = append(cleanupOrder, 1); mu.Unlock() },
		func() { mu.Lock(); cleanupOrder = append(cleanupOrder, 2); mu.Unlock() },
		func() { mu.Lock(); cleanupOrder = append(cleanupOrder, 3); mu.Unlock() },
	}

	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		shutdownOnSignal(e, sig, 1*time.Second, cleanups)
		close(done)
	}()

	sig <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdownOnSignal did not return within 3s")
	}
	waitStart()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []int{1, 2, 3}, cleanupOrder, "cleanups must run in registration order")
}

func TestShutdownOnSignal_NilCleanupsAreSkipped(t *testing.T) {
	e, waitStart := startEchoForTest(t)

	var ran int32
	cleanups := []func(){
		nil,
		func() { atomic.AddInt32(&ran, 1) },
		nil,
	}

	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		shutdownOnSignal(e, sig, 1*time.Second, cleanups)
		close(done)
	}()

	sig <- syscall.SIGINT

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdownOnSignal did not return within 3s")
	}
	waitStart()

	assert.Equal(t, int32(1), atomic.LoadInt32(&ran))
}

func TestShutdownOnSignal_ZeroTimeoutUsesDefault(t *testing.T) {
	// We can't directly observe the deadline, but we can confirm the
	// helper completes quickly even with timeout=0 — proving it doesn't
	// block forever.
	e, waitStart := startEchoForTest(t)

	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		shutdownOnSignal(e, sig, 0, nil)
		close(done)
	}()

	sig <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdownOnSignal with timeout=0 did not return within 3s")
	}
	waitStart()
}

func TestDefaultShutdownTimeoutIsTenSeconds(t *testing.T) {
	// 10s matches Cloud Run's default SIGTERM-to-SIGKILL grace window —
	// pinning prevents accidental drift.
	assert.Equal(t, 10*time.Second, DefaultShutdownTimeout)
}
