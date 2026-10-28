package recentshown

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type entry struct {
	member string
	score  float64
}

type fakeClient struct {
	mu    sync.Mutex
	sets  map[string][]entry
	ttls  map[string]time.Duration
	err   error
	block bool
	calls int
}

func newFake() *fakeClient {
	return &fakeClient{sets: map[string][]entry{}, ttls: map[string]time.Duration{}}
}

func (f *fakeClient) gate(ctx context.Context) error {
	f.calls++
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.err
}

func (f *fakeClient) sorted(key string) []entry {
	s := f.sets[key]
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].score != s[j].score {
			return s[i].score < s[j].score
		}
		return s[i].member < s[j].member
	})
	return s
}

func bound(s string) (val float64, exclusive bool) {
	switch s {
	case "-inf":
		return -1e300, false
	case "+inf":
		return 1e300, false
	}
	excl := strings.HasPrefix(s, "(")
	v, _ := strconv.ParseFloat(strings.TrimPrefix(s, "("), 64)
	return v, excl
}

func (f *fakeClient) ZAdd(ctx context.Context, key string, members ...redisv9.Z) *redisv9.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redisv9.NewIntCmd(ctx)
	if err := f.gate(ctx); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	for _, m := range members {
		f.sets[key] = append(f.sets[key], entry{member: m.Member.(string), score: m.Score})
	}
	cmd.SetVal(int64(len(members)))
	return cmd
}

func (f *fakeClient) ZRemRangeByScore(ctx context.Context, key, lo, hi string) *redisv9.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redisv9.NewIntCmd(ctx)
	if err := f.gate(ctx); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	l, lx := bound(lo)
	h, hx := bound(hi)
	var keep []entry
	for _, e := range f.sets[key] {
		in := (e.score > l || (!lx && e.score == l)) && (e.score < h || (!hx && e.score == h))
		if !in {
			keep = append(keep, e)
		}
	}
	f.sets[key] = keep
	return cmd
}

func (f *fakeClient) ZRemRangeByRank(ctx context.Context, key string, start, stop int64) *redisv9.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redisv9.NewIntCmd(ctx)
	if err := f.gate(ctx); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	s := f.sorted(key)
	n := int64(len(s))
	if start < 0 {
		start += n
	}
	if stop < 0 {
		stop += n
	}
	var keep []entry
	for i, e := range s {
		if int64(i) < start || int64(i) > stop {
			keep = append(keep, e)
		}
	}
	f.sets[key] = keep
	return cmd
}

func (f *fakeClient) ZRangeByScore(ctx context.Context, key string, opt *redisv9.ZRangeBy) *redisv9.StringSliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redisv9.NewStringSliceCmd(ctx)
	if err := f.gate(ctx); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	l, lx := bound(opt.Min)
	h, hx := bound(opt.Max)
	var out []string
	for _, e := range f.sorted(key) {
		if (e.score > l || (!lx && e.score == l)) && (e.score < h || (!hx && e.score == h)) {
			out = append(out, e.member)
		}
	}
	cmd.SetVal(out)
	return cmd
}

func (f *fakeClient) Expire(ctx context.Context, key string, d time.Duration) *redisv9.BoolCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redisv9.NewBoolCmd(ctx)
	if err := f.gate(ctx); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	f.ttls[key] = d
	cmd.SetVal(true)
	return cmd
}

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func TestRecordAndRecentCountTimesShown(t *testing.T) {
	f := newFake()
	s := New(f)
	ctx := context.Background()
	s.Record(ctx, "u1", "kielotv", []string{"a", "b", "a"}, t0)
	s.Record(ctx, "u1", "kielotv", []string{"a", "c"}, t0.Add(time.Minute))
	s.Record(ctx, "u1", "lehti", []string{"z"}, t0)
	s.Record(ctx, "u2", "kielotv", []string{"q"}, t0)

	got, err := s.Recent(ctx, "u1", "kielotv", t0.Add(2*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"a": 2, "b": 1, "c": 1}, got, "duplicates inside one batch count once")

	got, _ = s.Recent(ctx, "u1", "lehti", t0)
	assert.Equal(t, map[string]int{"z": 1}, got)
	got, _ = s.Recent(ctx, "u3", "kielotv", t0)
	assert.Empty(t, got)
	assert.Equal(t, DefaultWindow, f.ttls["recentshown:v1:u1:kielotv"])
}

func TestWindowExpiry(t *testing.T) {
	f := newFake()
	s := New(f, WithWindow(time.Hour))
	ctx := context.Background()
	s.Record(ctx, "u", "s", []string{"old"}, t0)
	s.Record(ctx, "u", "s", []string{"new"}, t0.Add(90*time.Minute))

	got, _ := s.Recent(ctx, "u", "s", t0.Add(90*time.Minute))
	assert.Equal(t, map[string]int{"new": 1}, got)
	assert.Len(t, f.sets["recentshown:v1:u:s"], 1, "Record trims expired entries")

	got, _ = s.Recent(ctx, "u", "s", t0.Add(3*time.Hour))
	assert.Empty(t, got)

	exact := New(newFake(), WithWindow(time.Hour))
	exact.Record(ctx, "u", "s", []string{"edge"}, t0)
	got, _ = exact.Recent(ctx, "u", "s", t0.Add(time.Hour))
	assert.Equal(t, map[string]int{"edge": 1}, got, "exactly a window old still counts")
}

func TestCapKeepsNewest(t *testing.T) {
	f := newFake()
	s := New(f, WithMaxEntries(5))
	ctx := context.Background()
	for i := range 4 {
		ids := []string{"b" + strconv.Itoa(i) + "x", "b" + strconv.Itoa(i) + "y"}
		s.Record(ctx, "u", "s", ids, t0.Add(time.Duration(i)*time.Minute))
	}
	got, _ := s.Recent(ctx, "u", "s", t0.Add(10*time.Minute))
	total := 0
	for _, n := range got {
		total += n
	}
	assert.Equal(t, 5, total)
	assert.NotContains(t, got, "b0x")
	assert.NotContains(t, got, "b0y")
	assert.Contains(t, got, "b3x")
	assert.Contains(t, got, "b3y")
}

func TestFailSoft(t *testing.T) {
	ctx := context.Background()
	var nilStore *Store
	nilStore.Record(ctx, "u", "s", []string{"a"}, t0)
	got, err := nilStore.Recent(ctx, "u", "s", t0)
	require.NoError(t, err)
	assert.Empty(t, got)

	noClient := New(nil)
	noClient.Record(ctx, "u", "s", []string{"a"}, t0)
	got, err = noClient.Recent(ctx, "u", "s", t0)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got)

	f := newFake()
	f.err = errors.New("redis down")
	s := New(f)
	s.Record(ctx, "u", "s", []string{"a"}, t0)
	got, err = s.Recent(ctx, "u", "s", t0)
	require.NoError(t, err)
	assert.Empty(t, got)

	ok := New(newFake())
	ok.Record(ctx, "", "s", []string{"a"}, t0)
	ok.Record(ctx, "u", "", []string{"a"}, t0)
	ok.Record(ctx, "u", "s", nil, t0)
	ok.Record(ctx, "u", "s", []string{""}, t0)
	got, _ = ok.Recent(ctx, "u", "s", t0)
	assert.Empty(t, got)
}

func TestReadAndWriteTimeouts(t *testing.T) {
	f := newFake()
	f.block = true
	s := New(f, WithReadTimeout(20*time.Millisecond), WithWriteTimeout(20*time.Millisecond))

	start := time.Now()
	got, err := s.Recent(context.Background(), "u", "s", t0)
	require.NoError(t, err)
	assert.Empty(t, got)
	s.Record(context.Background(), "u", "s", []string{"a"}, t0)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestRecordSurvivesCancelledCallerContext(t *testing.T) {
	f := newFake()
	s := New(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Record(ctx, "u", "s", []string{"a"}, t0)
	got, _ := s.Recent(context.Background(), "u", "s", t0)
	assert.Equal(t, map[string]int{"a": 1}, got, "a request context that ended must not drop the write")
}

func TestIdsWithSeparatorsRoundTrip(t *testing.T) {
	s := New(newFake())
	s.Record(context.Background(), "u", "s", []string{"a|b:c"}, t0)
	got, _ := s.Recent(context.Background(), "u", "s", t0)
	assert.Equal(t, map[string]int{"a|b:c": 1}, got)
}

func TestAgainstRealGoRedisClient(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	var _ Client = client

	s := New(client, WithMaxEntries(3), WithWindow(time.Hour))
	ctx := context.Background()
	now := time.Now()
	s.Record(ctx, "u", "s", []string{"a", "b"}, now)
	s.Record(ctx, "u", "s", []string{"a", "c"}, now.Add(time.Second))
	got, err := s.Recent(ctx, "u", "s", now.Add(2*time.Second))
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"a": 1, "b": 1, "c": 1}, got, "cap of 3 drops the oldest showing (a from the first batch)")
	assert.Equal(t, time.Hour, mr.TTL("recentshown:v1:u:s"))

	got, _ = s.Recent(ctx, "u", "s", now.Add(2*time.Hour))
	assert.Empty(t, got)
}

func TestDemote(t *testing.T) {
	order := []string{"a", "b", "c", "d", "e", "f"}
	cases := []struct {
		name   string
		recent map[string]int
		want   []string
	}{
		{"nil recent keeps order", nil, []string{"a", "b", "c", "d", "e", "f"}},
		{"empty recent keeps order", map[string]int{}, []string{"a", "b", "c", "d", "e", "f"}},
		{"seen move behind unseen, order kept", map[string]int{"a": 1, "c": 1}, []string{"b", "d", "e", "f", "a", "c"}},
		{"more often shown sorts later", map[string]int{"a": 3, "b": 1, "c": 2}, []string{"d", "e", "f", "b", "c", "a"}},
		{"ties keep original order", map[string]int{"b": 2, "d": 2, "f": 2}, []string{"a", "c", "e", "b", "d", "f"}},
		{"all seen equally keeps order", map[string]int{"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1}, order},
		{"ids not in the slice are ignored", map[string]int{"zzz": 9}, order},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]string(nil), order...)
			assert.Equal(t, tc.want, Demote(in, tc.recent))
			assert.Equal(t, order, in, "input is not modified")
		})
	}
	assert.Empty(t, Demote(nil, map[string]int{"a": 1}))
}
