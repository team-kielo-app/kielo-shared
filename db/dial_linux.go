//go:build linux

package db

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setTCPUserTimeout(d time.Duration) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil
		}
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
