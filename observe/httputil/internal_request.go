package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/team-kielo-app/kielo-shared/middleware"
)

// InternalAPIKeyHeader is the canonical header name for service-to-service
// API key authentication. Mirrors middleware.InternalAPIKeyHeader so callers
// don't have to reach into the middleware package just to get the constant.
const InternalAPIKeyHeader = middleware.InternalAPIKeyHeader

// PrepareInternalJSONRequest builds an HTTP request to a peer Kielo service
// with the standard internal-call boilerplate already applied:
//
//   - X-Internal-API-Key set when apiKey is non-empty
//   - X-Kielo-Learning-Language stamped from ctx via ApplyActiveLanguageHeader
//   - Content-Type: application/json when body is non-nil (JSON-marshaled)
//
// body=nil produces a request with http.NoBody. Otherwise body is
// json.Marshaled and wrapped in a bytes.Reader. Caller is still responsible
// for status-code checks, response decoding, and resp.Body.Close().
//
// Replaces the verbatim 8-line block — NewRequestWithContext + apiKey-set
// + ApplyActiveLanguageHeader (+ Content-Type when body) — that lived in
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
	ApplyActiveLanguageHeader(req)
	return req, nil
}
