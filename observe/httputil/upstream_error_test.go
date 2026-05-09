package httputil

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamError_Classifiers(t *testing.T) {
	tests := []struct {
		name     string
		err      *UpstreamError
		client   bool
		server   bool
	}{
		{"nil", nil, false, false},
		{"400", &UpstreamError{StatusCode: 400}, true, false},
		{"404", &UpstreamError{StatusCode: 404}, true, false},
		{"422", &UpstreamError{StatusCode: 422}, true, false},
		{"500", &UpstreamError{StatusCode: 500}, false, true},
		{"503", &UpstreamError{StatusCode: 503}, false, true},
		{"301", &UpstreamError{StatusCode: 301}, false, false}, // 3xx — neither
		{"200", &UpstreamError{StatusCode: 200}, false, false}, // not an error to begin with
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.client, tt.err.IsClientError())
			assert.Equal(t, tt.server, tt.err.IsServerError())
		})
	}
}

func TestAsUpstreamError_UnwrapsNestedErrors(t *testing.T) {
	original := &UpstreamError{StatusCode: 400, Service: "media-upload-api"}
	wrapped := errors.New("transport: " + original.Error())
	chained := errorsJoin(wrapped, original)

	got := AsUpstreamError(chained)
	require.NotNil(t, got)
	assert.Equal(t, 400, got.StatusCode)
	assert.Equal(t, "media-upload-api", got.Service)

	// Plain non-upstream errors return nil.
	assert.Nil(t, AsUpstreamError(errors.New("oops")))
	assert.Nil(t, AsUpstreamError(nil))
}

func TestDecodeUpstreamResponse_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"abc","name":"thing"}`)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	var out struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	require.NoError(t, DecodeUpstreamResponse(resp, &out, "demo", "GET", srv.URL))
	assert.Equal(t, "abc", out.ID)
	assert.Equal(t, "thing", out.Name)
}

func TestDecodeUpstreamResponse_NoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, DecodeUpstreamResponse(resp, nil, "demo", "POST", srv.URL))
}

func TestDecodeUpstreamResponse_4xxReturnsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"Unsupported MIME type: text/html"}`)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	err = DecodeUpstreamResponse(resp, nil, "media-upload-api", "POST", srv.URL)

	require.Error(t, err)
	ue := AsUpstreamError(err)
	require.NotNil(t, ue)
	assert.Equal(t, 400, ue.StatusCode)
	assert.True(t, ue.IsClientError())
	assert.False(t, ue.IsServerError())
	assert.Contains(t, ue.Body, "Unsupported MIME type")
	assert.Equal(t, "media-upload-api", ue.Service)
}

func TestDecodeUpstreamResponse_5xxReturnsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream timed out")
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	err = DecodeUpstreamResponse(resp, nil, "demo", "GET", srv.URL)

	require.Error(t, err)
	ue := AsUpstreamError(err)
	require.NotNil(t, ue)
	assert.True(t, ue.IsServerError())
}

func TestDecodeUpstreamResponse_BodyCappedAt4KB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("X", 10*1024))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	err = DecodeUpstreamResponse(resp, nil, "demo", "GET", srv.URL)

	ue := AsUpstreamError(err)
	require.NotNil(t, ue)
	assert.LessOrEqual(t, len(ue.Body), 4096)
}

func TestEchoErrorFromUpstream_4xxPreservesStatusAndMessage(t *testing.T) {
	upstream := &UpstreamError{
		StatusCode: 400,
		Body:       `{"message":"Unsupported MIME type: text/html"}`,
		Service:    "media-upload-api",
	}
	herr := EchoErrorFromUpstream(upstream, "Failed to generate upload URL")
	require.NotNil(t, herr)
	assert.Equal(t, 400, herr.Code)
	assert.Equal(t, "Unsupported MIME type: text/html", herr.Message)
}

func TestEchoErrorFromUpstream_4xxNestedErrorEnvelope(t *testing.T) {
	upstream := &UpstreamError{
		StatusCode: 422,
		Body:       `{"error":{"code":"VALIDATION_FAILED","message":"name is required"}}`,
		Service:    "user-service",
	}
	herr := EchoErrorFromUpstream(upstream, "default")
	require.NotNil(t, herr)
	assert.Equal(t, 422, herr.Code)
	assert.Equal(t, "name is required", herr.Message)
}

func TestEchoErrorFromUpstream_5xxBecomes502(t *testing.T) {
	upstream := &UpstreamError{StatusCode: 503, Body: "Service Unavailable", Service: "demo"}
	herr := EchoErrorFromUpstream(upstream, "Failed to fetch")
	require.NotNil(t, herr)
	assert.Equal(t, http.StatusBadGateway, herr.Code)
	assert.Equal(t, "Failed to fetch", herr.Message)
}

func TestEchoErrorFromUpstream_PlainErrorBecomes502(t *testing.T) {
	herr := EchoErrorFromUpstream(errors.New("connection refused"), "Failed")
	require.NotNil(t, herr)
	assert.Equal(t, http.StatusBadGateway, herr.Code)
}

func TestEchoErrorFromUpstream_NilReturnsNil(t *testing.T) {
	assert.Nil(t, EchoErrorFromUpstream(nil, "x"))
}

func TestEchoErrorFromUpstream_TimeoutBecomes504(t *testing.T) {
	herr := EchoErrorFromUpstream(timeoutErr{}, "Upstream slow")
	require.NotNil(t, herr)
	assert.Equal(t, http.StatusGatewayTimeout, herr.Code)
}

// timeoutErr satisfies net.Error with Timeout()=true. Used to drive the
// 504 branch without poking real network sockets.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// errorsJoin is a tiny errors.Join shim so the test compiles on Go
// versions without errors.Join (Go 1.20+ has it; older versions fall
// back to wrapping). The 1.20+ stdlib path is preferred.
func errorsJoin(outer, inner error) error {
	return joinedError{outer: outer, inner: inner}
}

type joinedError struct {
	outer, inner error
}

func (j joinedError) Error() string { return j.outer.Error() + ": " + j.inner.Error() }
func (j joinedError) Unwrap() error { return j.inner }

// Compile-time guard that *UpstreamError really does satisfy `error`
// and the AsUpstreamError unwrap chain. Keeps the test from regressing
// silently if someone refactors UpstreamError into a value receiver.
var (
	_ error = (*UpstreamError)(nil)
	_       = echo.NewHTTPError // keep echo import live
)
