package log

import (
	"bytes"
	"context"
	"io"
	stdlog "log"
	"log/slog"
	"strings"
	"sync"
)

// InstallDefault sets slog's default to a handler that writes what slog's own default writes ("<LEVEL> <msg> k=v",
// after the log package's prefix and flags) plus the trace fields of the call's context, so slog.InfoContext(ctx, ...)
// lines carry trace_id like [Printf] lines do.
//
// slog.SetDefault with any handler other than its own sends the log package's output through that handler and
// clears its flags; a handler that wrapped the old default would write back into log and loop. So this handler
// writes through its own logger, and the log package gets its writer, flags and prefix back: log.Printf lines are
// unchanged.
func InstallDefault() {
	w, flags, prefix := stdlog.Writer(), stdlog.Flags(), stdlog.Prefix()
	slog.SetDefault(slog.New(Handler(NewDefaultFormatHandler(w, prefix, flags))))
	stdlog.SetOutput(w)
	stdlog.SetFlags(flags)
	stdlog.SetPrefix(prefix)
}

// NewDefaultFormatHandler returns a handler that writes slog's default line format to w, through a log.Logger with
// the given prefix and flags. Wrap it with [Handler] to add the trace fields.
func NewDefaultFormatHandler(w io.Writer, prefix string, flags int) slog.Handler {
	s := &lineSink{out: stdlog.New(w, prefix, flags)}
	return &lineHandler{s: s, attrs: slog.NewTextHandler(&s.buf, &slog.HandlerOptions{ReplaceAttr: dropBuiltins})}
}

type lineSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
	out *stdlog.Logger
}

type lineHandler struct {
	s     *lineSink
	attrs slog.Handler
}

func dropBuiltins(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey || a.Key == slog.TimeKey) {
		return slog.Attr{}
	}
	return a
}

func (h *lineHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *lineHandler) Handle(ctx context.Context, r slog.Record) error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.buf.Reset()
	if err := h.attrs.Handle(ctx, r); err != nil {
		return err
	}
	line := r.Level.String() + " " + r.Message
	if rest := strings.TrimSuffix(h.s.buf.String(), "\n"); rest != "" {
		line += " " + rest
	}
	return h.s.out.Output(0, line)
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &lineHandler{s: h.s, attrs: h.attrs.WithAttrs(attrs)}
}

func (h *lineHandler) WithGroup(name string) slog.Handler {
	return &lineHandler{s: h.s, attrs: h.attrs.WithGroup(name)}
}
