// Package redisx holds the client settings every Kielo Go service should use
// for a Redis that is a cache, not a dependency: when the single Redis VM is
// down or hung, calls give up in a few hundred milliseconds, then stop being
// attempted at all for a few seconds, and the request carries on without it.
package redisx

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	DialTimeout  = 300 * time.Millisecond
	ReadTimeout  = 300 * time.Millisecond
	WriteTimeout = 300 * time.Millisecond

	breakerThreshold = 2
	breakerCooldown  = 3 * time.Second
)

// ErrBreakerOpen is returned without touching the network while Redis is
// considered down.
var ErrBreakerOpen = errors.New("redisx: circuit open, redis recently unreachable")

// Harden sets short dial/read/write timeouts, no command retries, a single dial attempt
// and context deadlines on opt, and returns opt. go-redis v9 ignores context
// deadlines unless ContextTimeoutEnabled is set, and its defaults (3s read,
// 5 dial attempts) hold a request for seconds per call.
func Harden(opt *redis.Options) *redis.Options {
	opt.DialTimeout = DialTimeout
	opt.ReadTimeout = ReadTimeout
	opt.WriteTimeout = WriteTimeout
	opt.MaxRetries = -1
	opt.DialerRetries = 1
	opt.ContextTimeoutEnabled = true
	return opt
}

// New returns a client with Harden applied and a circuit breaker installed, so
// a request that makes several cache calls pays one timeout, not one each.
func New(opt *redis.Options) *redis.Client {
	client := redis.NewClient(Harden(opt))
	client.AddHook(NewBreaker(breakerThreshold, breakerCooldown))
	return client
}

// Breaker is a go-redis hook that fails commands immediately after threshold
// consecutive transport failures and lets one probe through every cooldown
// until a command succeeds. Redis-reported errors (wrong type, nil reply) are
// not failures.
type Breaker struct {
	threshold int
	cooldown  time.Duration

	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold < 1 {
		threshold = 1
	}
	return &Breaker{threshold: threshold, cooldown: cooldown}
}

func (b *Breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return true
	}
	now := time.Now()
	if now.Before(b.openUntil) {
		return false
	}
	b.openUntil = now.Add(b.cooldown)
	return true
}

func (b *Breaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !isTransportFailure(err) {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = time.Now().Add(b.cooldown)
	}
}

func isTransportFailure(err error) bool {
	if err == nil || errors.Is(err, redis.Nil) || errors.Is(err, context.Canceled) {
		return false
	}
	var redisErr redis.Error
	return !errors.As(err, &redisErr)
}

// isHandshake reports whether cmds are the commands go-redis sends on a new
// connection. They run inside the command that triggered the dial, which
// already holds the breaker's slot, so they bypass it.
func isHandshake(cmds ...redis.Cmder) bool {
	for _, cmd := range cmds {
		switch cmd.Name() {
		case "hello", "auth", "client", "select", "readonly":
		default:
			return false
		}
	}
	return len(cmds) > 0
}

func (b *Breaker) DialHook(next redis.DialHook) redis.DialHook { return next }

func (b *Breaker) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if isHandshake(cmd) {
			return next(ctx, cmd)
		}
		if !b.allow() {
			return ErrBreakerOpen
		}
		err := next(ctx, cmd)
		b.record(err)
		return err
	}
}

func (b *Breaker) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if isHandshake(cmds...) {
			return next(ctx, cmds)
		}
		if !b.allow() {
			return ErrBreakerOpen
		}
		err := next(ctx, cmds)
		b.record(err)
		return err
	}
}
