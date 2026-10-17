// Package pgxcount counts the database round trips a request makes, so a test
// can hold a route to a budget and can mimic the prod pooler hop cost.
package pgxcount

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

type ctxKey struct{}

// Counter holds the round trips made under one context from WithCounter.
type Counter struct{ n atomic.Int64 }

// Trips is the number of round trips counted so far.
func (c *Counter) Trips() int64 { return c.n.Load() }

// WithCounter returns a context whose round trips are counted by the returned
// Counter. Contexts derived from it count into the same Counter.
func WithCounter(ctx context.Context) (context.Context, *Counter) {
	c := &Counter{}
	return context.WithValue(ctx, ctxKey{}, c), c
}

// Tracer is a pgx QueryTracer, BatchTracer and CopyFromTracer: each query,
// exec, batch and copy is one round trip. Install it as ConnConfig.Tracer.
type Tracer struct {
	// Delay is slept on every round trip; ~33 ms mimics the prod cross-region pooler.
	Delay time.Duration
	total atomic.Int64
}

// NewTracer returns a Tracer that charges delay on every round trip.
func NewTracer(delay time.Duration) *Tracer { return &Tracer{Delay: delay} }

// Total is every round trip the tracer has seen, whatever its context.
func (t *Tracer) Total() int64 { return t.total.Load() }

func (t *Tracer) hop(ctx context.Context) context.Context {
	t.total.Add(1)
	if c, ok := ctx.Value(ctxKey{}).(*Counter); ok {
		c.n.Add(1)
	}
	if t.Delay > 0 {
		time.Sleep(t.Delay)
	}
	return ctx
}

func (t *Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return t.hop(ctx)
}

func (t *Tracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (t *Tracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return t.hop(ctx)
}

func (t *Tracer) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}

func (t *Tracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func (t *Tracer) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceCopyFromStartData) context.Context {
	return t.hop(ctx)
}

func (t *Tracer) TraceCopyFromEnd(context.Context, *pgx.Conn, pgx.TraceCopyFromEndData) {}
