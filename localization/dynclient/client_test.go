package dynclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsert_PostsBodyWithAPIKey(t *testing.T) {
	var gotPath, gotAPIKey, gotCT string
	var gotReq UpsertRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("X-Internal-API-Key")
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(body, &gotReq))

		// Echo the row back with a fresh ID and inserted=true.
		row := DynamicTranslation{
			ID:             uuid.New(),
			ResourceType:   gotReq.ResourceType,
			ResourceID:     gotReq.ResourceID,
			SourceVersion:  gotReq.SourceVersion,
			LanguageCode:   gotReq.LanguageCode,
			TranslatedText: gotReq.TranslatedText,
			Status:         "machine",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(UpsertResponse{Row: &row, Inserted: true})
	}))
	defer srv.Close()

	c := New(srv.URL, "secret-key", nil)
	resp, err := c.Upsert(context.Background(), UpsertRequest{
		ResourceType:   "scenario.title",
		ResourceID:     "11111111-1111-1111-1111-111111111111",
		SourceVersion:  "abc",
		LanguageCode:   "fi",
		TranslatedText: "Otsikko",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Inserted)
	require.NotNil(t, resp.Row)
	assert.Equal(t, "scenario.title", resp.Row.ResourceType)

	assert.Equal(t, "/internal/api/v3/localization/dynamic", gotPath)
	assert.Equal(t, "secret-key", gotAPIKey)
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, "scenario.title", gotReq.ResourceType)
	assert.Equal(t, "Otsikko", gotReq.TranslatedText)
}

func TestUpsert_PropagatesNon2xxStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"resource_type is required"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key", nil)
	_, err := c.Upsert(context.Background(), UpsertRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "resource_type is required")
}

func TestFetchByResources_PostsBodyAndDecodes(t *testing.T) {
	var gotReq FetchRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/internal/api/v3/localization/dynamic/fetch", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotReq))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FetchResponse{
			Items: []DynamicTranslation{
				{
					ID:             uuid.New(),
					ResourceType:   "scenario.title",
					ResourceID:     gotReq.ResourceIDs[0],
					LanguageCode:   "fi",
					TranslatedText: "Otsikko",
					Status:         "machine",
				},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "k", nil)
	resp, err := c.FetchByResources(context.Background(), FetchRequest{
		ResourceTypes: []string{"scenario.title", "scenario.description"},
		ResourceIDs:   []string{"11111111-1111-1111-1111-111111111111"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Items, 1)
	assert.Equal(t, "Otsikko", resp.Items[0].TranslatedText)

	assert.Equal(t, []string{"scenario.title", "scenario.description"}, gotReq.ResourceTypes)
}

func TestUpsert_NilClientReturnsError(t *testing.T) {
	var c *Client
	_, err := c.Upsert(context.Background(), UpsertRequest{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "nil client"))
}
