package httputil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// UpstreamError carries the status code and body of a non-2xx response
// returned by a peer Kielo service so callers can map upstream failures
// to honest downstream responses instead of collapsing every error to
// 500 Internal Server Error.
//
// Why this type exists: the audit found ~14 internal clients all using
// the same `fmt.Errorf("X service returned status %d: %s", code, body)`
// pattern. Callers couldn't switch on the status, so a 400 from a peer
// (legitimate client error — bad MIME type, missing field, validation
// failure) bubbled up to the original caller as a 500. This produced
// two real bugs we tracked down:
//
//   - Mobile clients retried "transient 500" loops forever for what was
//     actually a permanent 4xx — wasted bandwidth + server load.
//   - Operators saw 500s in dashboards and paged for incidents that
//     were really just bad client requests.
//
// Use UpstreamError as the canonical typed error returned by every
// client method that hits a peer service. Handlers then unwrap it via
// errors.As (or the AsUpstreamError helper) and decide whether to
// propagate the status (4xx → 4xx) or wrap it as a gateway error
// (5xx / network → 502).
type UpstreamError struct {
	// StatusCode is the HTTP status the peer returned (e.g. 400, 503).
	StatusCode int
	// Body is the response body, capped at 4KB to keep error chains
	// reasonable. Caller-controlled — if the peer responded with the
	// canonical Kielo error envelope, it's preserved verbatim.
	Body string
	// Service is a short human label for the peer ("media-upload-api",
	// "kielolearn-engine"). Used in the error string and in the
	// `error.message` field of any wrapped echo.HTTPError.
	Service string
	// Method + URL identify which call failed, useful for log-grep.
	// URL should already have any auth tokens stripped by the caller.
	Method string
	URL    string
}

func (e *UpstreamError) Error() string {
	if e == nil {
		return "<nil *UpstreamError>"
	}
	if e.Method != "" && e.URL != "" {
		return fmt.Sprintf("%s %s %s: status %d: %s", e.Service, e.Method, e.URL, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("%s: status %d: %s", e.Service, e.StatusCode, e.Body)
}

// IsClientError reports whether the upstream returned 4xx — caller-side
// problem (bad input, validation failure, not-found, conflict). 4xx is
// never the BFF/proxy's fault; downstream callers should see the same
// 4xx.
func (e *UpstreamError) IsClientError() bool {
	return e != nil && e.StatusCode >= 400 && e.StatusCode < 500
}

// IsServerError reports whether the upstream returned 5xx — peer is
// broken. The downstream caller should see 502 Bad Gateway (or 504
// Gateway Timeout for transport-level timeouts handled separately).
func (e *UpstreamError) IsServerError() bool {
	return e != nil && e.StatusCode >= 500 && e.StatusCode < 600
}

// AsUpstreamError extracts an *UpstreamError from an error chain via
// errors.As. Returns nil when the chain doesn't contain one (e.g. for
// transport-level errors like network timeouts that come from
// http.Client.Do directly).
func AsUpstreamError(err error) *UpstreamError {
	var ue *UpstreamError
	if errors.As(err, &ue) {
		return ue
	}
	return nil
}

// DecodeUpstreamResponse is the canonical "got a response, now what?"
// helper for internal client methods. It takes the response from a
// peer service call and:
//
//   - If the status is in `okCodes` (defaults to {200, 201, 204} when
//     empty): closes the body and returns nil. If `into` is non-nil and
//     the body is non-empty, decodes JSON into `into` first.
//   - Otherwise: reads up to 4KB of the body and returns
//     *UpstreamError preserving status + body + service + URL.
//
// Always closes resp.Body.
//
// Pairs with PrepareInternalJSONRequest — the typical client method
// becomes:
//
//	req, err := httputil.PrepareInternalJSONRequest(ctx, "POST", url, key, body)
//	if err != nil { return nil, err }
//	resp, err := c.client.Do(req)
//	if err != nil { return nil, fmt.Errorf("send: %w", err) }
//	var out FooResponse
//	if err := httputil.DecodeUpstreamResponse(resp, &out, "media-upload-api", "POST", url); err != nil {
//	    return nil, err
//	}
//	return &out, nil
func DecodeUpstreamResponse(resp *http.Response, into any, service, method, url string, okCodes ...int) error {
	defer resp.Body.Close()

	if len(okCodes) == 0 {
		okCodes = []int{http.StatusOK, http.StatusCreated, http.StatusNoContent}
	}
	ok := false
	for _, code := range okCodes {
		if resp.StatusCode == code {
			ok = true
			break
		}
	}
	if !ok {
		// Cap captured body at 4KB so a misbehaving upstream can't
		// inflate the error chain; the canonical error envelope is
		// always well under that.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &UpstreamError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
			Service:    service,
			Method:     method,
			URL:        url,
		}
	}
	if into == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("decode %s response: %w", service, err)
	}
	return nil
}

// DecodeUpstreamEnvelope is the v3-aware sibling of DecodeUpstreamResponse.
// It expects success responses to carry the canonical ADR-004 §4 / ADR-006 §5
// `{"data": …}` envelope (emitted by every v3 group via
// SingletonEnvelopeWrapper) and decodes the `data` payload into `into`.
//
// Use this for inter-service calls that target a `/api/v3/...` endpoint
// on a peer that mounts MountV3Defaults. Internal routes (`/internal/...`)
// emit raw bodies and should keep using DecodeUpstreamResponse.
//
// Error handling matches DecodeUpstreamResponse — non-OK responses become
// *UpstreamError with the raw body preserved (the peer's error envelope is
// passed through verbatim, never re-wrapped).
func DecodeUpstreamEnvelope(resp *http.Response, into any, service, method, url string, okCodes ...int) error {
	defer resp.Body.Close()

	if len(okCodes) == 0 {
		okCodes = []int{http.StatusOK, http.StatusCreated, http.StatusNoContent}
	}
	ok := false
	for _, code := range okCodes {
		if resp.StatusCode == code {
			ok = true
			break
		}
	}
	if !ok {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &UpstreamError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
			Service:    service,
			Method:     method,
			URL:        url,
		}
	}
	if into == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode %s envelope: %w", service, err)
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("decode %s envelope: missing data field", service)
	}
	if err := json.Unmarshal(envelope.Data, into); err != nil {
		return fmt.Errorf("decode %s envelope payload: %w", service, err)
	}
	return nil
}

// EchoErrorFromUpstream maps a peer-call error to an *echo.HTTPError
// that preserves the upstream contract:
//
//   - *UpstreamError with 4xx  → 4xx with the upstream's body parsed as
//     a structured error (or `defaultMsg` if unparseable). Callers
//     normally pass this through to the original client.
//   - *UpstreamError with 5xx  → 502 Bad Gateway with `defaultMsg`. The
//     original caller learns "the gateway is fine but the peer is
//     broken" instead of "this BFF crashed".
//   - net.Error{Timeout: true}  → 504 Gateway Timeout with `defaultMsg`.
//   - any other transport error → 502 Bad Gateway with `defaultMsg`.
//   - nil                       → nil.
//
// `defaultMsg` is the human-friendly fallback ("Failed to generate
// upload URL"); use it when the upstream body isn't itself a useful
// message to surface.
func EchoErrorFromUpstream(err error, defaultMsg string) *echo.HTTPError {
	if err == nil {
		return nil
	}
	if ue := AsUpstreamError(err); ue != nil {
		if ue.IsClientError() {
			msg := upstreamErrorMessage(ue.Body, defaultMsg)
			return echo.NewHTTPError(ue.StatusCode, msg)
		}
		// 5xx (or any non-4xx, non-2xx like 3xx that wasn't followed)
		// means the peer is unhealthy — surface as a gateway error.
		return echo.NewHTTPError(http.StatusBadGateway, defaultMsg)
	}
	// Transport-level error. Distinguish timeout from connection /
	// DNS / TLS failures so retry-aware clients get the right signal.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return echo.NewHTTPError(http.StatusGatewayTimeout, defaultMsg)
	}
	return echo.NewHTTPError(http.StatusBadGateway, defaultMsg)
}

// upstreamErrorMessage extracts a human-readable message from the
// upstream body. Tries a few canonical shapes (Kielo's `error.message`,
// echo's `message`, plain text) and falls back to `defaultMsg`.
func upstreamErrorMessage(body, defaultMsg string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return defaultMsg
	}
	// Try to pluck a structured message out of common JSON shapes
	// without unmarshaling into a typed struct (we deliberately don't
	// want a dependency on any service's error model here).
	if msg := pluckJSONStringField(body, "message"); msg != "" {
		return msg
	}
	if msg := pluckJSONNestedField(body, "error", "message"); msg != "" {
		return msg
	}
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	return body
}

func pluckJSONStringField(body, field string) string {
	// Tiny tolerant scan: looks for `"<field>":"<value>"` in a flat
	// JSON object. Avoids json.Unmarshal so we don't add a typed
	// dependency, and tolerates extra whitespace + escaped quotes
	// inside the value.
	needle := `"` + field + `"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = strings.TrimLeft(rest[colon+1:], " \t")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	end := indexUnescapedQuote(rest)
	if end < 0 {
		return ""
	}
	return strings.ReplaceAll(rest[:end], `\"`, `"`)
}

func pluckJSONNestedField(body, outer, inner string) string {
	// `"<outer>":{ ..."<inner>":"..."` — handles the canonical
	// `{"error": {"message": "..."}}` shape without a full parser.
	outerNeedle := `"` + outer + `"`
	idx := strings.Index(body, outerNeedle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(outerNeedle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = strings.TrimLeft(rest[colon+1:], " \t")
	if !strings.HasPrefix(rest, "{") {
		return ""
	}
	return pluckJSONStringField(rest, inner)
}

func indexUnescapedQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip next
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}
