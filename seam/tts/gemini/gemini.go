// Package gemini is a ttsseam.Provider for Gemini TTS (generateContent with an
// AUDIO response). It is the single implementation the engine (Python mirror in
// kielo_shared/seam/tts/gemini_provider.py), kielo-convo's orchestrator and the
// Juka agent share.
//
// Gemini returns the clip as a complete WAV (audio/wav) or raw PCM (audio/L16).
// A WAV is never re-wrapped. contents is the plain text and nothing else: the
// model speaks any instruction aloud, so Request.Instructions is deliberately
// ignored and the language is pinned only through speechConfig.languageCode.
package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/team-kielo-app/kielo-shared/observe/httputil"
	ttsseam "github.com/team-kielo-app/kielo-shared/seam/tts"
)

const (
	defaultEndpoint = "https://generativelanguage.googleapis.com/v1beta"
	maxBodyBytes    = 64 << 20
)

// Output selects what Result.Audio holds.
type Output string

const (
	// OutputMP3 transcodes the WAV via Transcode (default).
	OutputMP3 Output = "mp3"
	// OutputWAV returns the WAV exactly as Gemini sent it (raw PCM gets a header).
	OutputWAV Output = "wav"
)

// Provider is safe for concurrent use.
type Provider struct {
	APIKey       string
	HTTPClient   *http.Client
	Endpoint     string
	DefaultModel string
	Output       Output
	// Transcode converts a WAV to MP3; nil means WAVToMP3.
	Transcode func(ctx context.Context, wav []byte, speed float64) ([]byte, error)
}

// New returns an MP3-output provider with a 30 s HTTP timeout when client is nil.
func New(apiKey, model string, client *http.Client) *Provider {
	if client == nil {
		client = httputil.NewClient(30 * time.Second)
	}
	return &Provider{APIKey: apiKey, HTTPClient: client, Endpoint: defaultEndpoint, DefaultModel: model, Output: OutputMP3}
}

func (p *Provider) model(req ttsseam.Request) string {
	if req.Model != "" {
		return req.Model
	}
	return p.DefaultModel
}

// ProviderID is "gemini-tts:<model>".
func (p *Provider) ProviderID(req ttsseam.Request) string {
	return "gemini-tts:" + p.model(req)
}

func clientErr(err error) error {
	return &ttsseam.Error{Class: ttsseam.ErrorClassClientError, Err: err}
}

func (p *Provider) validate(req ttsseam.Request) error {
	switch {
	case p.APIKey == "":
		return clientErr(errors.New("gemini API key not configured"))
	case strings.TrimSpace(req.Text) == "":
		return clientErr(errors.New("empty text"))
	case p.model(req) == "" || req.VoiceID == "":
		return clientErr(errors.New("gemini tts needs a model and a voice"))
	}
	return nil
}

// Synthesize implements ttsseam.Provider.
func (p *Provider) Synthesize(ctx context.Context, req ttsseam.Request) (*ttsseam.Result, error) {
	if err := p.validate(req); err != nil {
		return nil, err
	}
	started := time.Now()
	mime, data, err := p.generate(ctx, req)
	if err != nil {
		return nil, err
	}
	audio, err := AudioAsWAV(mime, data)
	if err != nil {
		return nil, err
	}
	if p.Output != OutputWAV {
		audio, err = p.transcode(ctx, audio, req.Speed)
		if err != nil {
			return nil, err
		}
	}
	if len(audio) == 0 {
		return nil, &ttsseam.Error{Class: ttsseam.ErrorClassEmptyResponse, Err: errors.New("gemini tts returned no audio")}
	}
	return &ttsseam.Result{Audio: audio, Provider: p.ProviderID(req), LatencyMs: time.Since(started).Milliseconds()}, nil
}

func (p *Provider) transcode(ctx context.Context, wav []byte, speed float64) ([]byte, error) {
	transcode := p.Transcode
	if transcode == nil {
		transcode = WAVToMP3
	}
	if speed <= 0 {
		speed = 1
	}
	mp3, err := transcode(ctx, wav, speed)
	if err != nil {
		var seamErr *ttsseam.Error
		if errors.As(err, &seamErr) {
			return nil, err
		}
		return nil, &ttsseam.Error{Class: ttsseam.ErrorClassUnknown, Err: err}
	}
	return mp3, nil
}

func buildBody(req ttsseam.Request) ([]byte, error) {
	speech := map[string]any{
		"voiceConfig": map[string]any{"prebuiltVoiceConfig": map[string]any{"voiceName": req.VoiceID}},
	}
	if tag := LanguageTag(req.LanguageCode); tag != "" {
		speech["languageCode"] = tag
	}
	return json.Marshal(map[string]any{
		"contents":         []any{map[string]any{"parts": []any{map[string]any{"text": req.Text}}}},
		"generationConfig": map[string]any{"responseModalities": []string{"AUDIO"}, "speechConfig": speech},
	})
}

type generateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				InlineData *struct {
					MimeType string `json:"mimeType"`
					Data     []byte `json:"data"`
				} `json:"inlineData"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (p *Provider) generate(ctx context.Context, req ttsseam.Request) (mimeType string, audio []byte, err error) {
	body, err := buildBody(req)
	if err != nil {
		return "", nil, &ttsseam.Error{Class: ttsseam.ErrorClassMarshal, Err: err}
	}
	endpoint := strings.TrimRight(p.Endpoint, "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/models/"+url.PathEscape(p.model(req))+":generateContent", bytes.NewReader(body))
	if err != nil {
		return "", nil, &ttsseam.Error{Class: ttsseam.ErrorClassMarshal, Err: err}
	}
	httpReq.Header.Set("x-goog-api-key", p.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return "", nil, &ttsseam.Error{Class: transportClass(ctx, err), Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, statusError(resp.StatusCode, raw)
	}
	return extractAudio(raw)
}

func statusError(status int, raw []byte) error {
	class := ttsseam.ErrorClassClientError
	if status >= http.StatusInternalServerError {
		class = ttsseam.ErrorClassServerError
	}
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	return &ttsseam.Error{Class: class, Err: fmt.Errorf("gemini tts status=%d body=%s", status, raw)}
}

func extractAudio(raw []byte) (mimeType string, audio []byte, err error) {
	var out generateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", nil, &ttsseam.Error{Class: ttsseam.ErrorClassReadBody, Err: err}
	}
	for _, candidate := range out.Candidates {
		for _, part := range candidate.Content.Parts {
			if part.InlineData != nil && len(part.InlineData.Data) > 0 {
				return part.InlineData.MimeType, part.InlineData.Data, nil
			}
		}
	}
	return "", nil, &ttsseam.Error{Class: ttsseam.ErrorClassEmptyResponse, Err: errors.New("gemini tts: no audio part")}
}

func transportClass(ctx context.Context, err error) ttsseam.ErrorClass {
	var netErr interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return ttsseam.ErrorClassTimeout
	}
	return ttsseam.ErrorClassConnection
}
