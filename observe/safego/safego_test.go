package safego

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoRestartSignalsWhenCancellationStopsWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	workerStarted := make(chan struct{})
	done := GoRestart(ctx, "test-restart-stop", func() {
		close(workerStarted)
		<-ctx.Done()
	})

	select {
	case <-workerStarted:
	case <-time.After(time.Second):
		t.Fatal("restarting worker did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("restarting worker did not signal completion")
	}
}

func TestGoRunsFunction(t *testing.T) {
	done := make(chan struct{})

	Go("test-run", func() {
		close(done)
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background function did not run")
	}
}

func TestGoRecoversPanic(t *testing.T) {
	var after atomic.Bool
	done := make(chan struct{})

	Go("test-panic", func() {
		defer close(done)
		panic("boom")
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background function did not complete")
	}

	Go("test-after-panic", func() {
		after.Store(true)
	})

	deadline := time.After(time.Second)
	for !after.Load() {
		select {
		case <-deadline:
			t.Fatal("runtime did not continue after recovered panic")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
