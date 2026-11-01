package log

import (
	"bytes"
	"context"
	stdlog "log"
	"strings"
	"testing"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestPrintfAppendsTheTraceSoOneGrepFindsTheRequest(t *testing.T) {
	var buf bytes.Buffer
	out, flags := stdlog.Writer(), stdlog.Flags()
	stdlog.SetOutput(&buf)
	stdlog.SetFlags(0)
	t.Cleanup(func() { stdlog.SetOutput(out); stdlog.SetFlags(flags) })

	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)
	Printf(ctx, "[translation-fallback] lang=%s\n", "sv")
	Println(ctx, "plain", 1)
	Printf(context.Background(), "no trace")
	Printf(nil, "nil context") //nolint:staticcheck // callers pass what they have

	got := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		"[translation-fallback] lang=sv trace_id=" + tc.TraceID,
		"plain 1 trace_id=" + tc.TraceID,
		"no trace",
		"nil context",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
