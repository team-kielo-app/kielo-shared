package safego

import "log"

// Go runs fn in a goroutine and recovers panics so detached background work
// cannot crash the process.
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
