//go:build !linux

package db

import (
	"syscall"
	"time"
)

// TCP_USER_TIMEOUT is Linux-only; Cloud Run runs Linux, local macOS builds
// keep the keepalive and connect limits.
func setTCPUserTimeout(time.Duration) func(network, address string, c syscall.RawConn) error {
	return nil
}
