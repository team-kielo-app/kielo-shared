package gemini

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	ttsseam "github.com/team-kielo-app/kielo-shared/seam/tts"
)

const languageFixture = "testdata/language_tags.json"

func TestLanguageMapMatchesSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(languageFixture)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	got := LanguageCodes()
	if len(got) != len(want) {
		t.Fatalf("map has %d entries, fixture %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
}

func TestLanguageMapMatchesPythonSource(t *testing.T) {
	src, err := os.ReadFile("../../../kielo_shared/seam/tts/languages.py")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range LanguageCodes() {
		if !strings.Contains(string(src), `"`+k+`": "`+v+`"`) {
			t.Errorf("languages.py lacks %q: %q", k, v)
		}
	}
	if n := strings.Count(string(src), `": "`); n != len(LanguageCodes()) {
		t.Errorf("languages.py has %d entries, Go %d", n, len(LanguageCodes()))
	}
}

func TestLanguageTag(t *testing.T) {
	cases := map[string]string{"fi": "fi-FI", "FI": "fi-FI", " zh ": "cmn-CN", "fi_FI": "fi-FI", "pt-BR": "pt-BR", "xx": "xx", "": ""}
	for in, want := range cases {
		if got := LanguageTag(in); got != want {
			t.Errorf("LanguageTag(%q)=%q want %q", in, got, want)
		}
	}
}

func testWAV() []byte { return PCMToWAV([]byte{1, 0, 2, 0, 3, 0, 4, 0}, 24000) }

type fakeServer struct {
	status int
	mime   string
	data   []byte
	body   []byte
	path   string
	key    string
}

func (f *fakeServer) start(t *testing.T) *Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.path, f.key = r.URL.Path, r.Header.Get("x-goog-api-key")
		f.body, _ = io.ReadAll(r.Body)
		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte("nope"))
			return
		}
		resp := map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{
			map[string]any{"inlineData": map[string]any{"mimeType": f.mime, "data": base64.StdEncoding.EncodeToString(f.data)}},
		}}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	p := New("key", "gemini-test", srv.Client())
	p.Endpoint = srv.URL + "/v1beta"
	p.Output = OutputWAV
	return p
}

func req(mod func(*ttsseam.Request)) ttsseam.Request {
	r := ttsseam.Request{Text: "Hei maailma", VoiceID: "Kore", LanguageCode: "sv", Task: "t", Instructions: "speak slowly"}
	if mod != nil {
		mod(&r)
	}
	return r
}

func TestRequestShapeAndLanguagePinning(t *testing.T) {
	f := &fakeServer{mime: "audio/wav", data: testWAV()}
	p := f.start(t)
	res, err := p.Synthesize(context.Background(), req(nil))
	if err != nil {
		t.Fatal(err)
	}
	if f.path != "/v1beta/models/gemini-test:generateContent" || f.key != "key" {
		t.Errorf("path=%q key=%q", f.path, f.key)
	}
	var body map[string]any
	if err := json.Unmarshal(f.body, &body); err != nil {
		t.Fatal(err)
	}
	parts := body["contents"].([]any)[0].(map[string]any)["parts"].([]any)
	if len(parts) != 1 || parts[0].(map[string]any)["text"] != "Hei maailma" {
		t.Errorf("contents must be the plain text only (instructions are spoken aloud): %v", parts)
	}
	gen := body["generationConfig"].(map[string]any)
	speech := gen["speechConfig"].(map[string]any)
	if speech["languageCode"] != "sv-SE" {
		t.Errorf("languageCode=%v", speech["languageCode"])
	}
	voice := speech["voiceConfig"].(map[string]any)["prebuiltVoiceConfig"].(map[string]any)["voiceName"]
	if voice != "Kore" || gen["responseModalities"].([]any)[0] != "AUDIO" {
		t.Errorf("voice=%v gen=%v", voice, gen)
	}
	if res.Provider != "gemini-tts:gemini-test" {
		t.Errorf("provider=%q", res.Provider)
	}
}

func TestEmptyLanguageOmitsLanguageCode(t *testing.T) {
	f := &fakeServer{mime: "audio/wav", data: testWAV()}
	p := f.start(t)
	if _, err := p.Synthesize(context.Background(), req(func(r *ttsseam.Request) { r.LanguageCode = "" })); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.body), "languageCode") {
		t.Errorf("languageCode sent for an empty language: %s", f.body)
	}
}

func TestWAVPassesThroughUntouched(t *testing.T) {
	wav := testWAV()
	f := &fakeServer{mime: "audio/wav", data: wav}
	res, err := f.start(t).Synthesize(context.Background(), req(nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Audio) != string(wav) || strings.Count(string(res.Audio), "RIFF") != 1 {
		t.Errorf("WAV was altered or re-wrapped")
	}
}

func TestRawPCMWrappedOnceWithItsRate(t *testing.T) {
	pcm := []byte{9, 0, 8, 0}
	f := &fakeServer{mime: "audio/L16;codec=pcm;rate=16000", data: pcm}
	res, err := f.start(t).Synthesize(context.Background(), req(nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Audio[:4]) != "RIFF" || string(res.Audio[44:]) != string(pcm) || res.Audio[24] != 0x80 || res.Audio[25] != 0x3e {
		t.Errorf("unexpected wrap: % x", res.Audio[:48])
	}
	back, err := WAVToPCM(res.Audio)
	if err != nil || string(back) != string(pcm) {
		t.Errorf("WAVToPCM=%v err=%v", back, err)
	}
}

func TestMP3OutputUsesTranscoderWithSpeed(t *testing.T) {
	f := &fakeServer{mime: "audio/wav", data: testWAV()}
	p := f.start(t)
	p.Output = OutputMP3
	var gotSpeed float64
	p.Transcode = func(_ context.Context, wav []byte, speed float64) ([]byte, error) {
		gotSpeed = speed
		return []byte("mp3"), nil
	}
	res, err := p.Synthesize(context.Background(), req(func(r *ttsseam.Request) { r.Speed = 1.25 }))
	if err != nil || string(res.Audio) != "mp3" || gotSpeed != 1.25 {
		t.Fatalf("res=%v err=%v speed=%v", res, err, gotSpeed)
	}
	if _, err := p.Synthesize(context.Background(), req(nil)); err != nil || gotSpeed != 1 {
		t.Errorf("default speed=%v err=%v", gotSpeed, err)
	}
	p.Transcode = func(context.Context, []byte, float64) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := p.Synthesize(context.Background(), req(nil)); ttsseam.ClassOf(err) != ttsseam.ErrorClassUnknown {
		t.Errorf("transcode failure class=%v", ttsseam.ClassOf(err))
	}
	p.Transcode = func(context.Context, []byte, float64) ([]byte, error) { return nil, nil }
	if _, err := p.Synthesize(context.Background(), req(nil)); ttsseam.ClassOf(err) != ttsseam.ErrorClassEmptyResponse {
		t.Errorf("empty transcode class=%v", ttsseam.ClassOf(err))
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		mime   string
		data   []byte
		want   ttsseam.ErrorClass
	}{
		{"429", 429, "", nil, ttsseam.ErrorClassClientError},
		{"503", 503, "", nil, ttsseam.ErrorClassServerError},
		{"no riff", 200, "audio/wav", []byte("nope"), ttsseam.ErrorClassReadBody},
		{"bad mime", 200, "audio/mpeg", []byte("x"), ttsseam.ErrorClassReadBody},
		{"no audio", 200, "audio/wav", nil, ttsseam.ErrorClassEmptyResponse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeServer{status: c.status, mime: c.mime, data: c.data}
			_, err := f.start(t).Synthesize(context.Background(), req(nil))
			if ttsseam.ClassOf(err) != c.want {
				t.Errorf("class=%v want %v (%v)", ttsseam.ClassOf(err), c.want, err)
			}
		})
	}
}

func TestTransportErrors(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	p := New("key", "m", &http.Client{Timeout: 50 * time.Millisecond})
	p.Endpoint = srv.URL
	if _, err := p.Synthesize(context.Background(), req(nil)); ttsseam.ClassOf(err) != ttsseam.ErrorClassTimeout {
		t.Errorf("timeout class=%v", ttsseam.ClassOf(err))
	}
	close(release)
	srv.Close()
	p.HTTPClient = &http.Client{Timeout: time.Second}
	if _, err := p.Synthesize(context.Background(), req(nil)); ttsseam.ClassOf(err) != ttsseam.ErrorClassConnection {
		t.Errorf("connection class=%v", ttsseam.ClassOf(err))
	}
}

func TestValidationMakesNoCall(t *testing.T) {
	f := &fakeServer{mime: "audio/wav", data: testWAV()}
	p := f.start(t)
	for name, mod := range map[string]func(*ttsseam.Request){
		"blank text": func(r *ttsseam.Request) { r.Text = "  " },
		"no voice":   func(r *ttsseam.Request) { r.VoiceID = "" },
	} {
		if _, err := p.Synthesize(context.Background(), req(mod)); ttsseam.ClassOf(err) != ttsseam.ErrorClassClientError {
			t.Errorf("%s: class=%v", name, ttsseam.ClassOf(err))
		}
	}
	noKey := *p
	noKey.APIKey = ""
	noModel := *p
	noModel.DefaultModel = ""
	for name, prov := range map[string]*Provider{"no key": &noKey, "no model": &noModel} {
		if _, err := prov.Synthesize(context.Background(), req(nil)); ttsseam.ClassOf(err) != ttsseam.ErrorClassClientError {
			t.Errorf("%s: class=%v", name, ttsseam.ClassOf(err))
		}
	}
	if f.path != "" {
		t.Errorf("server was called: %s", f.path)
	}
}

func TestWAVToMP3WithLocalFFmpeg(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not available")
	}
	mp3, err := WAVToMP3(context.Background(), PCMToWAV(make([]byte, 48000), 24000), 1.5)
	if err != nil || len(mp3) == 0 {
		t.Fatalf("len=%d err=%v", len(mp3), err)
	}
}
