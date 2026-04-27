package httputil

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

func TestPrepareInternalJSONRequest_NilBody(t *testing.T) {
	req, err := PrepareInternalJSONRequest(context.Background(), http.MethodGet, "https://svc.test/api", "secret", nil)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "https://svc.test/api", req.URL.String())
	assert.Equal(t, "secret", req.Header.Get(InternalAPIKeyHeader))
	assert.Empty(t, req.Header.Get("Content-Type"), "GET with no body shouldn't set Content-Type")
	assert.Equal(t, http.NoBody, req.Body)
}

func TestPrepareInternalJSONRequest_WithBody(t *testing.T) {
	payload := map[string]any{"increment_by": 1, "item_id": "abc"}
	req, err := PrepareInternalJSONRequest(context.Background(), http.MethodPost, "https://svc.test/inc", "k", payload)
	require.NoError(t, err)

	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "k", req.Header.Get(InternalAPIKeyHeader))

	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &got))
	assert.Equal(t, float64(1), got["increment_by"])
	assert.Equal(t, "abc", got["item_id"])
}

func TestPrepareInternalJSONRequest_EmptyAPIKeyOmitsHeader(t *testing.T) {
	req, err := PrepareInternalJSONRequest(context.Background(), http.MethodGet, "https://svc.test/x", "", nil)
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get(InternalAPIKeyHeader),
		"empty apiKey must not set X-Internal-API-Key (some callsites treat presence as auth-attempt)")
}

func TestPrepareInternalJSONRequest_StampsActiveLanguage(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	req, err := PrepareInternalJSONRequest(ctx, http.MethodGet, "https://svc.test/x", "k", nil)
	require.NoError(t, err)
	assert.Equal(t, "sv", req.Header.Get(KieloLearningLanguageHeader))
}

func TestPrepareInternalJSONRequest_NoLanguageInCtx(t *testing.T) {
	req, err := PrepareInternalJSONRequest(context.Background(), http.MethodGet, "https://svc.test/x", "k", nil)
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get(KieloLearningLanguageHeader))
}

func TestPrepareInternalJSONRequest_BodyMarshalError(t *testing.T) {
	// Channels can't be JSON-marshaled — confirms the helper surfaces marshal errors
	// rather than producing a request with a corrupted body.
	_, err := PrepareInternalJSONRequest(context.Background(), http.MethodPost, "https://svc.test/x", "k", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal request body")
}
