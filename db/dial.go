package db

import (
	"net"
	"time"
)

// Network limits for every pooled connection. A Cloud Run instance whose path
// to the database stalls must fail its queries in seconds; on 2026-10-10 one
// user-service instance held every request for five minutes because nothing
// below the request bounded a query whose bytes were never acknowledged.
const (
	connectTimeout = 5 * time.Second
	// tcpUserTimeout aborts a connection when data it sent stays unacknowledged
	// this long (Linux TCP_USER_TIMEOUT). A slow query sends nothing while the
	// server works, so this never cuts off legitimate long statements.
	tcpUserTimeout    = 30 * time.Second
	keepAliveIdle     = 15 * time.Second
	keepAliveInterval = 5 * time.Second
	keepAliveCount    = 3
)

func newDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: connectTimeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepAliveIdle,
			Interval: keepAliveInterval,
			Count:    keepAliveCount,
		},
		Control: setTCPUserTimeout(tcpUserTimeout),
	}
}
