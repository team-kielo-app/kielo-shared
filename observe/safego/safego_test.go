package safego

import (
	"sync/atomic"
	"testing"
	"time"
)

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
