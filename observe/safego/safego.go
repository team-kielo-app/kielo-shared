package safego

import (
	"context"
	"log"
	"time"
)

// Go runs fn in a goroutine and recovers panics so detached background work
// cannot crash the process. Use this for one-shot work: after a panic (or
// normal return) the goroutine ends. For a long-lived worker LOOP that must
// not stay dead inside a healthy process, use GoRestart.
func Go(name string, fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				if name == "" {
					log.Printf("WARN: background goroutine panicked: %v", rec)
					return
				}
				log.Printf("WARN: background goroutine %s panicked: %v", name, rec)
			}
		}()
		fn()
	}()
}

const (
	goRestartInitialBackoff = time.Second
	goRestartMaxBackoff     = 30 * time.Second
	// A run that stayed up at least this long is treated as healthy, so the
	// backoff resets — an occasional panic after hours of uptime shouldn't
	// inherit the backoff from a long-ago crash.
	goRestartHealthyRun = time.Minute
)

// GoRestart runs a long-lived worker loop in a goroutine and RESTARTS it after
// a panic or an unexpected return, with exponential backoff (1s → 30s cap).
// It stops cleanly when ctx is canceled — so normal shutdown does not trigger
// a restart. Unlike Go, which recovers-and-exits (leaving the loop permanently
// dead in an otherwise-healthy process), this keeps critical processors alive.
func GoRestart(ctx context.Context, name string, fn func()) {
	go func() {
		backoff := goRestartInitialBackoff
		for {
			if ctx.Err() != nil {
				return
			}
			start := time.Now()
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("ERROR: worker %s panicked: %v — restarting after backoff", name, rec)
					}
				}()
				fn()
			}()
			if ctx.Err() != nil {
				return
			}
			// fn returned or panicked unexpectedly. If it had been running
			// healthily for a while, reset the backoff before retrying.
			if time.Since(start) >= goRestartHealthyRun {
				backoff = goRestartInitialBackoff
			}
			log.Printf("WARN: worker %s exited unexpectedly; restarting in %s", name, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < goRestartMaxBackoff {
				backoff *= 2
				if backoff > goRestartMaxBackoff {
					backoff = goRestartMaxBackoff
				}
			}
		}
	}()
}
