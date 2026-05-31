package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/team-kielo-app/kielo-shared/middleware"
	"github.com/team-kielo-app/kielo-shared/observe"
)

// InternalAPIKeyHeader is the canonical header name for service-to-service
// API key authentication. Mirrors middleware.InternalAPIKeyHeader so callers
// don't have to reach into the middleware package just to get the constant.
const InternalAPIKeyHeader = middleware.InternalAPIKeyHeader

// PrepareInternalJSONRequest builds an HTTP request to a peer Kielo service
// with the standard internal-call boilerplate already applied:
//
//   - X-Internal-API-Key set when apiKey is non-empty
//   - learning_language_code query param stamped from ctx via ApplyActiveLanguageQuery
//   - X-Kielo-Learning-Language header stamped from ctx via ApplyActiveLanguageHeader
//   - Content-Type: application/json when body is non-nil (JSON-marshaled)
//
// body=nil produces a request with http.NoBody. Otherwise body is
// json.Marshaled and wrapped in a bytes.Reader. Caller is still responsible
// for status-code checks, response decoding, and resp.Body.Close().
//
// Replaces the verbatim 8-line block — NewRequestWithContext + apiKey-set
// + ApplyActiveLanguageQuery (+ Content-Type when body) — that lived in
// every internal client method (~30 callsites across kielo-cms,
// kielo-content-service, kielo-mobile-bff, kielo-user-service).
func PrepareInternalJSONRequest(
	ctx context.Context,
	method, url, apiKey string,
	body any,
) (*http.Request, error) {
	var reader io.Reader = http.NoBody
	hasBody := false
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(jsonBody)
		hasBody = true
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set(InternalAPIKeyHeader, apiKey)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	ApplyActiveLanguageQuery(req)
	ApplyActiveLanguageHeader(req)
	// Sweep QQQQ: forward the active support (UI/translation) language
	// from ctx onto every internal request. Sibling to the learning-
	// language pair above. Pre-QQQQ only kielo-content-service's
	// klearn_client.go (Sweep PPPP) and kielo-mobile-bff's
	// utils/http.go::injectSupportLanguageQueryParam implemented this
	// per-service; every other Go HTTP client that talks to an
	// upstream returning localized user-facing content silently
	// dropped the signal. Engine's get_support_language FastAPI dep
	// then fell back to "en" -> raw source language returned to
	// non-Finnish learners (root cause of the user-reported
	// concept-hub localization leak that drove Sweep OOOO+PPPP).
	ApplySupportLanguageQuery(req)
	ApplySupportLanguageHeader(req)
	// Forward the active trace context onto the outbound request so the
	// downstream service can treat this call as a child span and the
	// mobile-issued X-Client-Trace-Id flows end-to-end through every
	// internal hop. No-op when ctx carries no trace (background workers
	// without a request scope).
	if tc, ok := observe.FromContext(ctx); ok {
		observe.InjectHeaders(req.Header, tc)
	}
	return req, nil
}
