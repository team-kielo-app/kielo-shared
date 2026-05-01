// Package log provides a structured logging factory that automatically enriches
// log records with trace context from [observe.TraceContext].
//
// Usage:
//
//	logger := log.New("kielo-cms")
//	ctx := observe.WithContext(ctx, tc)
//	slog.InfoContext(ctx, "request handled") // → includes trace_id, span_id, request_id
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/observe"
)

type loggerContextKey struct{}

// Option configures a logger created by [New].
type Option func(*config)

type config struct {
	level  slog.Level
	output io.Writer
}

// WithLevel sets the minimum log level. Default is determined by LOG_LEVEL env.
func WithLevel(level slog.Level) Option {
	return func(c *config) { c.level = level }
}

// WithOutput sets the output writer. Default is os.Stderr.
func WithOutput(w io.Writer) Option {
	return func(c *config) { c.output = w }
}

// New creates an [*slog.Logger] with a JSON handler that:
//   - includes a "service" field on every record
//   - automatically adds trace_id, span_id, request_id from context
//   - reads LOG_LEVEL env var for the minimum level (default: info)
func New(service string, opts ...Option) *slog.Logger {
	cfg := &config{
		level:  parseLogLevel(os.Getenv("LOG_LEVEL")),
		output: os.Stderr,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	jsonHandler := slog.NewJSONHandler(cfg.output, &slog.HandlerOptions{
		Level: cfg.level,
	})

	wrapped := Handler(jsonHandler)
	return slog.New(wrapped).With("service", service)
}

// Handler wraps an [slog.Handler] to automatically inject trace fields from
// the record's context into every log entry. This means any code using
// slog.InfoContext(ctx, ...) gets trace_id/span_id/request_id for free.
func Handler(base slog.Handler) slog.Handler {
	return &traceHandler{base: base}
}

// FromContext retrieves a logger stored via [WithContext]. If none is stored,
// returns [slog.Default] wrapped with [Handler] so trace fields still appear.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerContextKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.New(Handler(slog.Default().Handler()))
}

// WithContext stores a logger in the context for later retrieval via [FromContext].
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

// traceHandler is an slog.Handler that enriches records with trace context.
type traceHandler struct {
	base slog.Handler
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, record slog.Record) error {
	if tc, ok := observe.FromContext(ctx); ok && !tc.IsZero() {
		record.AddAttrs(
			slog.String("trace_id", tc.TraceID),
			slog.String("span_id", tc.SpanID),
			slog.String("request_id", tc.RequestID),
		)
	}
	if lang, ok := db.LanguageFromContext(ctx); ok && lang != "" {
		record.AddAttrs(slog.String("learning_language_code", lang))
	}
	return h.base.Handle(ctx, record)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{base: h.base.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{base: h.base.WithGroup(name)}
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
