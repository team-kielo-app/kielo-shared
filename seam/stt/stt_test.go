package stt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/team-kielo-app/kielo-shared/seam/stt"
)

func TestDeepgramProviderTranscribesWithLanguageAndKeyterms(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token test-key" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.URL.Query().Get("language"); got != "sv" {
			t.Fatalf("language = %q", got)
		}
		if got := r.URL.Query()["keyterm"]; len(got) != 2 || got[0] != "kanelbulle" {
			t.Fatalf("keyterms = %#v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":{"channels":[{"alternatives":[{"transcript":"Kan jag få kaffe?","confidence":0.93}]}]}}`))
	}))
	defer server.Close()

	provider := stt.NewDeepgramProvider("test-key", server.Client())
	provider.Endpoint = server.URL
	result, err := provider.Transcribe(context.Background(), stt.Request{
		Audio:       []byte("wav"),
		ContentType: "audio/wav",
		Language:    "sv",
		Keyterms:    []string{"kanelbulle", "kaffe"},
	})
	if err != nil {
		t.Fatalf("Transcribe: %v", err)
	}
	if result.Transcript != "Kan jag få kaffe?" {
		t.Fatalf("transcript = %q", result.Transcript)
	}
	if result.Provider != "deepgram:nova-3" {
		t.Fatalf("provider = %q", result.Provider)
	}
}

func TestDeepgramProviderRejectsUnsupportedLanguage(t *testing.T) {
	provider := stt.NewDeepgramProvider("test-key", nil)
	_, err := provider.Transcribe(context.Background(), stt.Request{Audio: []byte("wav"), Language: "en"})
	if got := stt.ClassOf(err); got != stt.ErrorClassClientError {
		t.Fatalf("ClassOf = %q", got)
	}
}

func TestDeepgramProviderRejectsEmptyTranscript(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":{"channels":[{"alternatives":[{"transcript":"  ","confidence":0}]}]}}`))
	}))
	defer server.Close()

	provider := stt.NewDeepgramProvider("test-key", server.Client())
	provider.Endpoint = server.URL
	_, err := provider.Transcribe(context.Background(), stt.Request{
		Audio: []byte("wav"), Language: "fi",
	})
	if got := stt.ClassOf(err); got != stt.ErrorClassEmptyResponse {
		t.Fatalf("ClassOf = %q", got)
	}
}
