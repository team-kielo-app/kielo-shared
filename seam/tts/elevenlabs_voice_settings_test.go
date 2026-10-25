package tts_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/team-kielo-app/kielo-shared/seam/tts"
)

func f64(v float64) *float64 { return &v }

func voiceSettings(t *testing.T, configure func(*tts.ElevenLabsProvider), req tts.Request) map[string]float64 {
	t.Helper()
	var got map[string]float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			VoiceSettings map[string]float64 `json:"voice_settings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode: %v", err)
		}
		got = payload.VoiceSettings
		_, _ = w.Write([]byte("mp3"))
	}))
	defer srv.Close()
	p := tts.NewElevenLabsProvider("k", srv.Client())
	p.Endpoint = srv.URL
	configure(p)
	req.Text, req.VoiceID, req.Task = "Hei", "v", "t"
	if _, err := p.Synthesize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestElevenLabsVoiceSettings(t *testing.T) {
	none := func(*tts.ElevenLabsProvider) {}
	if got := voiceSettings(t, none, tts.Request{Speed: 1}); got["stability"] != 0.5 || got["similarity_boost"] != 0.75 || got["speed"] != 1 {
		t.Errorf("defaults changed: %v", got)
	}
	if got := voiceSettings(t, none, tts.Request{}); got != nil {
		t.Errorf("voice_settings sent without speed or overrides: %v", got)
	}
	provider := func(p *tts.ElevenLabsProvider) { p.Stability, p.SimilarityBoost = f64(0.3), f64(0.9) }
	if got := voiceSettings(t, provider, tts.Request{Speed: 1}); got["stability"] != 0.3 || got["similarity_boost"] != 0.9 {
		t.Errorf("provider override: %v", got)
	}
	got := voiceSettings(t, provider, tts.Request{Stability: f64(0.2)})
	if got["stability"] != 0.2 || got["similarity_boost"] != 0.9 {
		t.Errorf("request wins, provider fills the rest: %v", got)
	}
	if _, hasSpeed := got["speed"]; hasSpeed {
		t.Errorf("speed sent without a speed: %v", got)
	}
	if got := voiceSettings(t, none, tts.Request{SimilarityBoost: f64(0.1)}); got["stability"] != 0.5 || got["similarity_boost"] != 0.1 {
		t.Errorf("single override: %v", got)
	}
}
