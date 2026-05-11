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

func TestApplyActiveLanguageQuery_StampsFromContext(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)

	ApplyActiveLanguageQuery(req)

	assert.Equal(t, "sv", req.URL.Query().Get(LearningLanguageQueryParam))
}

func TestApplyActiveLanguageQuery_OmittedWhenContextHasNoLanguage(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)

	ApplyActiveLanguageQuery(req)

	assert.Empty(t, req.URL.Query().Get(LearningLanguageQueryParam))
}

func TestApplyActiveLanguageQuery_PreservesExplicitOverride(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/?learning_language_code=sv", nil)
	require.NoError(t, err)

	ApplyActiveLanguageQuery(req)

	assert.Equal(t, "sv", req.URL.Query().Get(LearningLanguageQueryParam))
}

func TestApplyActiveLanguageQuery_NilRequestDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	ApplyActiveLanguageQuery(nil)
}

func TestApplyActiveLanguageQuery_EndToEndOverHTTP(t *testing.T) {
	var observed string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r.URL.Query().Get(LearningLanguageQueryParam)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	ApplyActiveLanguageQuery(req)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, "sv", observed)
}
