// Package redisx holds the client settings every Kielo Go service should use
// for a Redis that is a cache, not a dependency: when the single Redis VM is
// down or hung, calls give up in a few hundred milliseconds and the request
// carries on without it.
package redisx

import (
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	DialTimeout  = 300 * time.Millisecond
	ReadTimeout  = 300 * time.Millisecond
	WriteTimeout = 300 * time.Millisecond
)

// Harden sets short dial/read/write timeouts, one retry, a single dial attempt
// and context deadlines on opt, and returns opt. go-redis v9 ignores context
// deadlines unless ContextTimeoutEnabled is set, and its defaults (3s read,
// 5 dial attempts) hold a request for seconds per call.
func Harden(opt *redis.Options) *redis.Options {
	opt.DialTimeout = DialTimeout
	opt.ReadTimeout = ReadTimeout
	opt.WriteTimeout = WriteTimeout
	opt.MaxRetries = 1
	opt.DialerRetries = 1
	opt.ContextTimeoutEnabled = true
	return opt
}
