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
	// A supported LanguageCode is needed to reach the transport at all: Upsert
	// refuses unsupported codes locally because they cannot satisfy the
	// languages foreign key. This test is about propagating a SERVER error, so
	// it must get past that precondition rather than trip it.
	_, err := c.Upsert(context.Background(), UpsertRequest{LanguageCode: "vi"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "resource_type is required")
}

// The languages foreign key makes an unsupported code unwritable, so Upsert
// must refuse it locally instead of spending a round-trip to learn that.
// seam_autotranslate_comms hit this with "fa" across ui.string,
// notification.title and notification.body; content did the same with cs/sl.
func TestUpsert_RefusesUnsupportedLanguageWithoutCallingServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "key", nil)
	for _, code := range []string{"fa", "cs", "sl", ""} {
		_, err := c.Upsert(context.Background(), UpsertRequest{
			ResourceType: "ui.string", ResourceID: "x", LanguageCode: code,
			TranslatedText: "t", SourceVersion: "v",
		})
		require.Error(t, err, "code %q must be refused", code)
		require.ErrorIs(t, err, ErrUnsupportedLanguage,
			"callers distinguish skip from failure via this sentinel")
	}
	assert.False(t, called,
		"no HTTP request may be made for a locale the foreign key cannot accept")
}

// The refusal must be exact: anything the foreign key accepts still goes out,
// including a code that only becomes valid after folding (ars -> ar).
func TestUpsert_SupportedAndFoldableLanguagesStillReachServer(t *testing.T) {
	var gotCodes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req UpsertRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotCodes = append(gotCodes, req.LanguageCode)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"row":null,"inserted":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key", nil)
	for _, code := range []string{"vi", "fi", "ars"} {
		_, err := c.Upsert(context.Background(), UpsertRequest{
			ResourceType: "ui.string", ResourceID: "x", LanguageCode: code,
			TranslatedText: "t", SourceVersion: "v",
		})
		require.NoError(t, err, "code %q is supported and must be sent", code)
	}
	assert.Equal(t, []string{"vi", "fi", "ars"}, gotCodes)
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
