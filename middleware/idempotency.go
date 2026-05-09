// idempotency.go: dedupe POST/PATCH/DELETE retries by Idempotency-Key.
//
// Mobile apps on flaky connections love to retry mutations: scenario
// start, achievement grant, subscription cancel. Without an idempotency
// key, a transport-layer retry of a 200-OK that the client missed
// produces a duplicate side effect (two scenarios, two grants, two
// subscription mutations). RFC draft-ietf-httpapi-idempotency-key
// pins a single header — `Idempotency-Key: <client-chosen string>` —
// and tells the server to remember the response for one TTL window
// and replay it on retry.
//
// Storage: a Redis instance keyed by
//   "idem:<route_signature>:<auth_subject>:<key>"
// where route_signature = METHOD + path-template (so /me/items/{a}/{b}
// shares one slot regardless of a/b values), auth_subject = the JWT
// user id (or X-API-Key fingerprint for service-to-service), and key
// is the client-supplied header value. Per-subject namespacing prevents
// one client's key from leaking another's response.
//
// Concurrency: SetNX with a "lock" sentinel handles the read-then-write
// race. The first request wins, runs the handler, then writes the real
// captured response over the lock. Concurrent retries see the lock and
// short-circuit to a 409 IDEMPOTENT_REQUEST_IN_FLIGHT — clients then
// poll or retry after a backoff, at which point the captured response
// is ready.
//
// Skip rules:
//   - GET / HEAD / OPTIONS: always pass through (already idempotent).
//   - Missing Idempotency-Key header: pass through (opt-in by client).
//   - Errors during the upstream handler are NOT cached — clients
//     should be able to retry past a transient failure with the same
//     key and get a fresh attempt.
//
// Apply per-route or per-group; safe to mount on the entire /api/v3
// surface since the missing-header case is a no-op.

package middleware

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

// IdempotencyOptions configures the middleware. Zero values are valid:
// ResponseTTL defaults to 24h, LockTTL to 30s, KeyMaxLen to 255.
type IdempotencyOptions struct {
	// Redis is the storage backend. Required — pass nil to disable.
	Redis *redis.Client
	// ResponseTTL is how long a captured response stays replayable.
	// Mobile clients typically retry within seconds-to-minutes; 24h
	// gives a comfortable margin for app-suspend / wake-up cycles.
	ResponseTTL time.Duration
	// LockTTL bounds how long a concurrent retry waits before the
	// in-flight lock auto-expires. Should be longer than the slowest
	// expected handler runtime; default 30s is generous for any
	// non-LLM handler.
	LockTTL time.Duration
	// KeyMaxLen rejects pathologically large keys (defense against a
	// client choosing a megabyte string and blowing out Redis memory).
	KeyMaxLen int
	// Subject extracts the auth subject (user id, API-key fingerprint)
	// from the request context — used to namespace keys per caller so
	// a malicious client can't poison another client's idempotency
	// slot. Falls back to "anonymous" when nil or returning empty.
	Subject func(c echo.Context) string
}

// idempotencyResult is the captured shape stored in Redis between the
// initial request and any replay. Keep small and JSON-serializable.
type idempotencyResult struct {
	Status int               `json:"status"`
	Body   []byte            `json:"body"`
	Header map[string]string `json:"header,omitempty"`
}

// captureResponseWriter buffers the handler's writes so we can serialize
// the full response after the chain returns. Mirrors the pattern in
// SingletonEnvelopeWrapper.
type captureResponseWriter struct {
	http.ResponseWriter
	status      int
	buf         bytes.Buffer
	wrote       bool
	passThrough bool
	hijacked    bool
}

func (w *captureResponseWriter) WriteHeader(code int) {
	if w.passThrough {
		w.ResponseWriter.WriteHeader(code)
		w.wrote = true
		w.status = code
		return
	}
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.passThrough {
		return w.ResponseWriter.Write(b)
	}
	return w.buf.Write(b)
}

// Hijack implements http.Hijacker so reverse-proxy WebSocket upgrades
// can take over the underlying TCP connection through this wrapper.
// The embedded http.ResponseWriter only promotes interface methods
// (Header / Write / WriteHeader); Hijack lives on the concrete type
// behind the interface and isn't promoted, so we have to forward it
// explicitly. Idempotency caching is meaningless for an upgraded
// connection — the response body is empty and the protocol switch
// can't be replayed — so the safe behaviour on upgrade is to
// short-circuit caching and hand control to the underlying writer.
func (w *captureResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("kielo-shared/middleware: underlying ResponseWriter is not an http.Hijacker")
	}
	w.hijacked = true
	w.passThrough = true
	return hj.Hijack()
}

// Flush implements http.Flusher so SSE / streaming handlers behave
// correctly when this middleware is in the chain. Body buffering is
// abandoned on first flush — caching a partial stream would replay a
// truncated response on retry, which is worse than skipping the cache.
func (w *captureResponseWriter) Flush() {
	w.enablePassThrough()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying ResponseWriter so http.NewResponseController
// in callers can find any interface (Pusher, ReadDeadlineSetter, …) we
// haven't explicitly proxied.
func (w *captureResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *captureResponseWriter) enablePassThrough() {
	if w.passThrough {
		return
	}
	w.passThrough = true
	if w.wrote {
		w.ResponseWriter.WriteHeader(w.status)
	}
	if w.buf.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

// resolvedIdempotencyOptions holds Idempotency middleware options after
// zero-value defaults have been resolved. Internal helper type — splits
// the validated config out of the public IdempotencyOptions struct so
// the per-request handler can be a small flat function.
type resolvedIdempotencyOptions struct {
	rdb         *redis.Client
	responseTTL time.Duration
	lockTTL     time.Duration
	keyMaxLen   int
	subjectFn   func(c echo.Context) string
}

// Idempotency returns Echo middleware enforcing the Idempotency-Key
// contract above. Safe to mount on a group containing GETs (they pass
// through unchanged).
func Idempotency(opts IdempotencyOptions) echo.MiddlewareFunc {
	if opts.Redis == nil {
		// No-op middleware. Lets callers wire it unconditionally and
		// flip Redis on later without code changes.
		return func(next echo.HandlerFunc) echo.HandlerFunc { return next }
	}

	resolved := resolvedIdempotencyOptions{
		rdb:         opts.Redis,
		responseTTL: opts.ResponseTTL,
		lockTTL:     opts.LockTTL,
		keyMaxLen:   opts.KeyMaxLen,
		subjectFn:   opts.Subject,
	}
	if resolved.responseTTL <= 0 {
		resolved.responseTTL = 24 * time.Hour
	}
	if resolved.lockTTL <= 0 {
		resolved.lockTTL = 30 * time.Second
	}
	if resolved.keyMaxLen <= 0 {
		resolved.keyMaxLen = 255
	}
	if resolved.subjectFn == nil {
		resolved.subjectFn = func(c echo.Context) string { return "anonymous" }
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return handleIdempotentRequest(c, next, resolved)
		}
	}
}

func handleIdempotentRequest(c echo.Context, next echo.HandlerFunc, o resolvedIdempotencyOptions) error {
	method := c.Request().Method
	// GET/HEAD/OPTIONS are already idempotent by HTTP spec.
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return next(c)
	}

	rawKey := strings.TrimSpace(c.Request().Header.Get("Idempotency-Key"))
	if rawKey == "" {
		return next(c)
	}
	if len(rawKey) > o.keyMaxLen {
		return echo.NewHTTPError(
			http.StatusBadRequest,
			fmt.Sprintf("Idempotency-Key exceeds %d chars", o.keyMaxLen),
		)
	}

	subject := strings.TrimSpace(o.subjectFn(c))
	if subject == "" {
		subject = "anonymous"
	}

	// Route signature uses Echo's path template (not the concrete URL)
	// so two requests to /me/items/A and /me/items/B with the same key
	// share one slot — that's the correct semantic since the key is
	// supposed to identify a logical operation, not a specific URL.
	routeSig := method + " " + c.Path()
	redisKey := buildIdempotencyKey(routeSig, subject, rawKey)

	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()

	// SetNX with the lock sentinel. ok=true means winning request,
	// runs the handler. Otherwise somebody else got there first.
	ok, err := o.rdb.SetNX(ctx, redisKey, "lock", o.lockTTL).Result()
	if err == nil && ok {
		return runAndCache(c, next, o.rdb, redisKey, o.responseTTL)
	}

	return replayCachedIdempotentResponse(ctx, c, next, o.rdb, redisKey)
}

func replayCachedIdempotentResponse(
	ctx context.Context,
	c echo.Context,
	next echo.HandlerFunc,
	rdb *redis.Client,
	redisKey string,
) error {
	cached, err := rdb.Get(ctx, redisKey).Bytes()
	if err == redis.Nil || len(cached) == 0 {
		return next(c)
	}
	if err != nil {
		// Redis unavailable — fail open rather than blocking real
		// traffic on infra issues.
		return next(c)
	}
	if string(cached) == "lock" {
		// Original request still running.
		return c.JSON(http.StatusConflict, map[string]any{
			"error": map[string]string{
				"code":    "IDEMPOTENT_REQUEST_IN_FLIGHT",
				"message": "Original request with this Idempotency-Key is still in flight. Retry after a brief delay.",
			},
		})
	}

	var stored idempotencyResult
	if json.Unmarshal(cached, &stored) != nil {
		return next(c)
	}
	for k, v := range stored.Header {
		c.Response().Header().Set(k, v)
	}
	c.Response().Header().Set("Idempotent-Replayed", "true")
	return c.Blob(stored.Status, "application/json", stored.Body)
}

// runAndCache wraps the handler with a capture writer, runs it, and
// stores the captured response in Redis if the handler returned 2xx.
// 4xx/5xx are NOT cached — clients can retry past transient failures
// with the same key and get fresh attempts.
func runAndCache(
	c echo.Context,
	next echo.HandlerFunc,
	rdb *redis.Client,
	redisKey string,
	ttl time.Duration,
) error {
	originalWriter := c.Response().Writer
	capture := &captureResponseWriter{ResponseWriter: originalWriter}
	c.Response().Writer = capture

	defer func() { c.Response().Writer = originalWriter }()

	err := next(c)

	if capture.passThrough || capture.hijacked {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rdb.Del(ctx, redisKey).Err()
		return err
	}

	status := capture.status
	if status == 0 {
		status = http.StatusOK
	}
	bodyBytes := capture.buf.Bytes()

	// Mirror the captured response back to the real writer so the
	// client gets the response from this run.
	if status != 0 {
		originalWriter.WriteHeader(status)
	}
	if len(bodyBytes) > 0 {
		_, _ = originalWriter.Write(bodyBytes)
	}

	// Only cache 2xx — 4xx/5xx might be transient.
	if err == nil && status >= 200 && status < 300 {
		stored := idempotencyResult{
			Status: status,
			Body:   bodyBytes,
		}
		// Capture only the headers safe to replay; intentionally
		// skip Set-Cookie, Authorization echoes, Date.
		for _, h := range []string{"Content-Type", "Content-Encoding", "Cache-Control"} {
			if v := capture.ResponseWriter.Header().Get(h); v != "" {
				if stored.Header == nil {
					stored.Header = map[string]string{}
				}
				stored.Header[h] = v
			}
		}
		if data, mErr := json.Marshal(stored); mErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = rdb.Set(ctx, redisKey, data, ttl).Err()
		}
	} else {
		// Release the lock so the client can immediately retry past
		// the failure with the same key.
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = rdb.Del(ctx, redisKey).Err()
	}

	return err
}

func buildIdempotencyKey(routeSig, subject, rawKey string) string {
	// Hash the (subject, key) pair to keep Redis keys bounded length
	// regardless of caller-chosen string. Route signature stays in
	// plaintext so it's grep-able during incidents.
	h := sha256.Sum256([]byte(subject + ":" + rawKey))
	return "idem:" + routeSig + ":" + hex.EncodeToString(h[:])
}
