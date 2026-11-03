package log

import (
	"bytes"
	"context"
	"errors"
	stdlog "log"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestALineReadsAsSlogsDefaultWithTheTraceAppended(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(Handler(NewDefaultFormatHandler(&out, "", 0))).With("svc", "convo")
	tc := observe.New()

	logger.InfoContext(observe.WithContext(context.Background(), tc), "GDPR purge complete", "user_id", "u 1")
	logger.Debug("hidden")
	logger.WithGroup("g").Warn("no trace", "k", 1)

	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	want0 := `INFO GDPR purge complete svc=convo user_id="u 1" trace_id=` + tc.TraceID
	if len(got) != 2 || !strings.HasPrefix(got[0], want0) || got[1] != "WARN no trace svc=convo g.k=1" {
		t.Fatalf("lines = %q", got)
	}
}

func TestInstallDefaultLeavesTheLogPackageAsItWas(t *testing.T) {
	var out bytes.Buffer
	w, flags, prefix, def := stdlog.Writer(), stdlog.Flags(), stdlog.Prefix(), slog.Default()
	t.Cleanup(func() { slog.SetDefault(def); stdlog.SetOutput(w); stdlog.SetFlags(flags); stdlog.SetPrefix(prefix) })
	stdlog.SetOutput(&out)
	stdlog.SetFlags(0)
	stdlog.SetPrefix("svc: ")

	InstallDefault()
	stdlog.Printf("plain %d", 1)
	slog.Info("structured", "k", "v")
	tc := observe.New()
	slog.InfoContext(observe.WithContext(context.Background(), tc), "traced")

	want := "svc: plain 1\nsvc: INFO structured k=v\nsvc: INFO traced trace_id=" + tc.TraceID + " span_id=" + tc.SpanID +
		" request_id=" + tc.RequestID + "\n"
	if got := out.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if stdlog.Prefix() != "svc: " || stdlog.Flags() != 0 {
		t.Fatalf("log package prefix/flags changed: %q %d", stdlog.Prefix(), stdlog.Flags())
	}
}

func TestLinesMatchSlogsOwnDefault(t *testing.T) {
	var std, ours bytes.Buffer
	w, flags := stdlog.Writer(), stdlog.Flags()
	t.Cleanup(func() { stdlog.SetOutput(w); stdlog.SetFlags(flags) })
	stdlog.SetOutput(&std)
	stdlog.SetFlags(0)
	emit := func(l *slog.Logger) {
		l.Info("plain")
		l.Error("PubSub/UserDeleted: DB purge failed", "user_id", "a b", "error", errors.New(`pq: "x" failed`))
		l.With("svc", "convo").WithGroup("req").Warn("slow", "took", 1500*time.Millisecond, "n", 3, "ok", true)
		l.Info("empty", "s", "", "nil", nil, slog.Group("g", "k", "v"))
	}
	emit(slog.New(slog.Default().Handler()))
	emit(slog.New(NewDefaultFormatHandler(&ours, "", 0)))
	if std.String() != ours.String() {
		t.Fatalf("slog default:\n%s\nours:\n%s", std.String(), ours.String())
	}
}
