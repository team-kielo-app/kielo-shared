package log

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"

	"github.com/team-kielo-app/kielo-shared/observe"
)

// Printf is the standard library's log.Printf with the request's trace appended (" trace_id=<32 hex>"), so one grep
// finds a request's lines in every service. A context without a trace logs the line as log.Printf would.
func Printf(ctx context.Context, format string, args ...any) {
	_ = stdlog.Output(2, WithTrace(ctx, fmt.Sprintf(format, args...)))
}

// Println is log.Println with the request's trace appended.
func Println(ctx context.Context, args ...any) {
	_ = stdlog.Output(2, WithTrace(ctx, fmt.Sprintln(args...)))
}

// Print is log.Print with the request's trace appended.
func Print(ctx context.Context, args ...any) {
	_ = stdlog.Output(2, WithTrace(ctx, fmt.Sprint(args...)))
}

// WithTrace is msg with " trace_id=<id>" at its end when ctx carries a trace. The id goes last so log-based metrics
// that match a message's text keep matching.
func WithTrace(ctx context.Context, msg string) string {
	msg = strings.TrimRight(msg, "\n")
	if ctx == nil {
		return msg
	}
	if tc, ok := observe.FromContext(ctx); ok && !tc.IsZero() {
		return msg + " trace_id=" + tc.TraceID
	}
	return msg
}
