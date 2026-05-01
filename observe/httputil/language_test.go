package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

func TestApplyActiveLanguageHeader_StampsFromContext(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)

	ApplyActiveLanguageHeader(req)

	assert.Equal(t, "sv", req.Header.Get(KieloLearningLanguageHeader))
}

func TestApplyActiveLanguageHeader_OmittedWhenContextHasNoLanguage(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)

	ApplyActiveLanguageHeader(req)

	assert.Empty(t, req.Header.Get(KieloLearningLanguageHeader))
	_, present := req.Header[KieloLearningLanguageHeader]
	assert.False(t, present, "header should not be set when ctx has no language")
}

func TestApplyActiveLanguageHeader_PreservesExplicitOverride(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)
	req.Header.Set(KieloLearningLanguageHeader, "sv")

	ApplyActiveLanguageHeader(req)

	assert.Equal(t, "sv", req.Header.Get(KieloLearningLanguageHeader))
}

func TestApplyActiveLanguageHeader_NilRequestDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	ApplyActiveLanguageHeader(nil)
}

func TestApplyActiveLanguageHeader_EndToEndOverHTTP(t *testing.T) {
	var observed string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r.Header.Get(KieloLearningLanguageHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	ApplyActiveLanguageHeader(req)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, "sv", observed)
}
