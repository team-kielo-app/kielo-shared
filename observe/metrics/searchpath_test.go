package metrics

import (
	"bytes"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSetServiceName_RoundTrip(t *testing.T) {
	// Save + restore so the test doesn't pollute the process-global for
	// other tests in the package.
	prev := serviceName.Load()
	t.Cleanup(func() {
		if prev != nil {
			serviceName.Store(prev)
		} else {
			serviceName.Store("")
		}
	})

	SetServiceName("")
	if got := ServiceName(); got != "unknown" {
		t.Errorf("ServiceName() with empty = %q, want %q", got, "unknown")
	}

	SetServiceName("kielo-cms")
	if got := ServiceName(); got != "kielo-cms" {
		t.Errorf("ServiceName() = %q, want %q", got, "kielo-cms")
	}
}

func TestPerLanguageSearchPathFallbackEmit_IncrementsCounter(t *testing.T) {
	prev := serviceName.Load()
	t.Cleanup(func() {
		if prev != nil {
			serviceName.Store(prev)
		} else {
			serviceName.Store("")
		}
		ResetPerLanguageSearchPathFallbackState()
	})
	ResetPerLanguageSearchPathFallbackState()
	SetServiceName("kielo-cms")

	PerLanguageSearchPathFallbackEmit("kielotv.list_brands", false)
	PerLanguageSearchPathFallbackEmit("kielotv.list_brands", false)
	PerLanguageSearchPathFallbackEmit("other_site", true)

	if got := testutil.ToFloat64(
		PerLanguageSearchPathFallbackTotal.WithLabelValues("kielo-cms", "kielotv.list_brands"),
	); got != 2 {
		t.Errorf("kielotv.list_brands count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(
		PerLanguageSearchPathFallbackTotal.WithLabelValues("kielo-cms", "other_site"),
	); got != 1 {
		t.Errorf("other_site count = %v, want 1", got)
	}
}

func TestPerLanguageSearchPathFallbackEmit_DefaultsCallsite(t *testing.T) {
	prev := serviceName.Load()
	t.Cleanup(func() {
		if prev != nil {
			serviceName.Store(prev)
		} else {
			serviceName.Store("")
		}
		ResetPerLanguageSearchPathFallbackState()
	})
	ResetPerLanguageSearchPathFallbackState()
	SetServiceName("kielo-cms")

	PerLanguageSearchPathFallbackEmit("", false)

	if got := testutil.ToFloat64(
		PerLanguageSearchPathFallbackTotal.WithLabelValues("kielo-cms", "unknown"),
	); got != 1 {
		t.Errorf("empty callsite should map to label \"unknown\"; got count %v", got)
	}
}

func TestPerLanguageSearchPathFallbackEmit_WarnOnceUnexpected(t *testing.T) {
	prev := serviceName.Load()
	prevLogger := slog.Default()
	var logbuf safeBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		if prev != nil {
			serviceName.Store(prev)
		} else {
			serviceName.Store("")
		}
		ResetPerLanguageSearchPathFallbackState()
	})
	ResetPerLanguageSearchPathFallbackState()
	SetServiceName("kielo-cms")

	PerLanguageSearchPathFallbackEmit("site_a", false)
	PerLanguageSearchPathFallbackEmit("site_a", false)
	PerLanguageSearchPathFallbackEmit("site_a", false)

	out := logbuf.String()
	warnCount := strings.Count(out, "level=WARN")
	if warnCount != 1 {
		t.Errorf("expected exactly 1 WARN, got %d. Output:\n%s", warnCount, out)
	}
	// Subsequent calls fell to DEBUG.
	debugCount := strings.Count(out, "level=DEBUG")
	if debugCount != 2 {
		t.Errorf("expected exactly 2 DEBUG follow-ups, got %d. Output:\n%s", debugCount, out)
	}
}

func TestPerLanguageSearchPathFallbackEmit_DebugOnlyWhenExpected(t *testing.T) {
	prev := serviceName.Load()
	prevLogger := slog.Default()
	var logbuf safeBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		if prev != nil {
			serviceName.Store(prev)
		} else {
			serviceName.Store("")
		}
		ResetPerLanguageSearchPathFallbackState()
	})
	ResetPerLanguageSearchPathFallbackState()
	SetServiceName("kielo-cms")

	PerLanguageSearchPathFallbackEmit("site_b", true)
	PerLanguageSearchPathFallbackEmit("site_b", true)

	out := logbuf.String()
	if strings.Contains(out, "level=WARN") {
		t.Errorf("expectedFallback=true must not emit WARN. Output:\n%s", out)
	}
	if got := strings.Count(out, "level=DEBUG"); got != 2 {
		t.Errorf("expected 2 DEBUG lines, got %d. Output:\n%s", got, out)
	}
}

// safeBuffer wraps bytes.Buffer with an atomic.Pointer for concurrent-safe
// writes from slog handlers. slog writes synchronously from the caller's
// goroutine in this test, but the type guards against future changes
// where a wrapper might fan out asynchronously.
type safeBuffer struct {
	buf atomic.Pointer[bytes.Buffer]
}

func (s *safeBuffer) get() *bytes.Buffer {
	b := s.buf.Load()
	if b != nil {
		return b
	}
	fresh := &bytes.Buffer{}
	if s.buf.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return s.buf.Load()
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	return s.get().Write(p)
}

func (s *safeBuffer) String() string {
	return s.get().String()
}
