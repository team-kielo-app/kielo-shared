// Package redisdown gives tests a Redis address that is down: one that
// refuses connections and one that accepts them and never answers.
package redisdown

import (
	"context"
	"net"
	"sync"
	"testing"
)

// Refused returns an address nothing listens on.
func Refused(t testing.TB) string {
	t.Helper()
	ln, err := listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// Hang returns the address of a listener that accepts connections and never
// replies. Accepted connections are closed when the test ends.
func Hang(t testing.TB) string {
	t.Helper()
	ln, err := listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

func listen() (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
}
