// Package recentshown remembers what a learner was recently shown on each
// surface so rankers can move repeats behind unseen items. It is a soft
// signal: a nil client, a Redis error or a timeout yields an empty result and
// never blocks or fails a feed.
package recentshown

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	redisv9 "github.com/redis/go-redis/v9"
)

const (
	DefaultWindow       = 24 * time.Hour
	DefaultMaxEntries   = 200
	DefaultReadTimeout  = 150 * time.Millisecond
	DefaultWriteTimeout = 500 * time.Millisecond

	keyPrefix = "recentshown:v1:"
)

// Client is the slice of the go-redis API the store uses; redis.Cmdable
// (*redis.Client, *redis.ClusterClient) satisfies it.
type Client interface {
	ZAdd(ctx context.Context, key string, members ...redisv9.Z) *redisv9.IntCmd
	ZRemRangeByScore(ctx context.Context, key, min, max string) *redisv9.IntCmd
	ZRemRangeByRank(ctx context.Context, key string, start, stop int64) *redisv9.IntCmd
	ZRangeByScore(ctx context.Context, key string, opt *redisv9.ZRangeBy) *redisv9.StringSliceCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redisv9.BoolCmd
}

// Option customizes a Store.
type Option func(*Store)

func WithWindow(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.window = d
		}
	}
}

func WithMaxEntries(n int) Option {
	return func(s *Store) {
		if n > 0 {
			s.maxEntries = n
		}
	}
}

func WithReadTimeout(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.readTimeout = d
		}
	}
}

func WithWriteTimeout(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.writeTimeout = d
		}
	}
}

// Store keeps one sorted set per user and surface: each entry is one showing
// (member "<unix-nano>.<n>|<id>", score unix milliseconds), trimmed to the
// window and to the newest MaxEntries, with the key's TTL set to the window.
type Store struct {
	client       Client
	window       time.Duration
	maxEntries   int
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// New returns a Store over client. A nil client gives a Store whose methods do
// nothing.
func New(client Client, opts ...Option) *Store {
	s := &Store{
		client:       client,
		window:       DefaultWindow,
		maxEntries:   DefaultMaxEntries,
		readTimeout:  DefaultReadTimeout,
		writeTimeout: DefaultWriteTimeout,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Store) enabled() bool { return s != nil && s.client != nil }

func key(userID, surface string) string { return keyPrefix + userID + ":" + surface }

func millis(t time.Time) int64 { return t.UnixMilli() }

// Record notes that ids were shown to the learner on the surface at now. It is
// safe to call from a goroutine; the write is bounded by a short timeout and
// every error is swallowed.
func (s *Store) Record(ctx context.Context, userID, surface string, ids []string, now time.Time) {
	if !s.enabled() || userID == "" || surface == "" || len(ids) == 0 {
		return
	}
	defer func() { _ = recover() }()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.writeTimeout)
	defer cancel()

	k := key(userID, surface)
	score := float64(millis(now))
	seen := make(map[string]struct{}, len(ids))
	members := make([]redisv9.Z, 0, len(ids))
	prefix := strconv.FormatInt(now.UnixNano(), 10)
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		members = append(members, redisv9.Z{Score: score, Member: prefix + "." + strconv.Itoa(len(members)) + "|" + id})
	}
	if len(members) == 0 {
		return
	}
	if err := s.client.ZAdd(ctx, k, members...).Err(); err != nil {
		return
	}
	cutoff := strconv.FormatInt(millis(now.Add(-s.window)), 10)
	_ = s.client.ZRemRangeByScore(ctx, k, "-inf", "("+cutoff).Err()
	_ = s.client.ZRemRangeByRank(ctx, k, 0, int64(-s.maxEntries-1)).Err()
	_ = s.client.Expire(ctx, k, s.window).Err()
}

// Recent returns id -> times shown within the window ending at now. Any
// failure returns an empty map.
func (s *Store) Recent(ctx context.Context, userID, surface string, now time.Time) (out map[string]int, err error) {
	out = map[string]int{}
	if !s.enabled() || userID == "" || surface == "" {
		return out, nil
	}
	defer func() {
		if r := recover(); r != nil {
			out, err = map[string]int{}, nil
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()

	members, qerr := s.client.ZRangeByScore(ctx, key(userID, surface), &redisv9.ZRangeBy{
		Min: strconv.FormatInt(millis(now.Add(-s.window)), 10),
		Max: "+inf",
	}).Result()
	if qerr != nil {
		return map[string]int{}, nil
	}
	for _, m := range members {
		if _, id, ok := strings.Cut(m, "|"); ok && id != "" {
			out[id]++
		}
	}
	return out, nil
}

// Demote returns order with recently shown ids moved behind unseen ones: a
// stable sort by times shown ascending, so unseen ids keep their relative
// order first, then ids shown once, then twice, and so on. order is not
// modified.
func Demote(order []string, recent map[string]int) []string {
	out := make([]string, len(order))
	copy(out, order)
	if len(recent) == 0 {
		return out
	}
	sort.SliceStable(out, func(i, j int) bool { return recent[out[i]] < recent[out[j]] })
	return out
}
