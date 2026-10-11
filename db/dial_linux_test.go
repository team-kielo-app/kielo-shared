//go:build linux

package db

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDialerSetsUserTimeoutAndKeepalive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
		}
	}()

	conn, err := newDialer().DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var userTimeout, keepAlive, idle int
	require.NoError(t, raw.Control(func(fd uintptr) {
		userTimeout, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
		keepAlive, _ = unix.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		idle, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
	}))
	assert.Equal(t, int(tcpUserTimeout.Milliseconds()), userTimeout)
	assert.Equal(t, 1, keepAlive)
	assert.Equal(t, int(keepAliveIdle.Seconds()), idle)
}
