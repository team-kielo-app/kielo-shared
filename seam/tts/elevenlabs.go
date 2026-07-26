package tts

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
)

const (
	defaultElevenLabsEndpoint = "https://api.elevenlabs.io/v1/text-to-speech"
	defaultElevenLabsModel    = "eleven_flash_v2_5"
)

type ElevenLabsProvider struct {
	APIKey       string
	HTTPClient   *http.Client
	Endpoint     string
	DefaultModel string
}

func NewElevenLabsProvider(apiKey string, client *http.Client) *ElevenLabsProvider {
	if client == nil {
		client = httputil.NewClient(30 * time.Second)
	}
	return &ElevenLabsProvider{
		APIKey:       apiKey,
		HTTPClient:   client,
		Endpoint:     defaultElevenLabsEndpoint,
		DefaultModel: defaultElevenLabsModel,
	}
}

func (p *ElevenLabsProvider) ProviderID(req Request) string {
	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	return "elevenlabs-tts:" + model
}

func (p *ElevenLabsProvider) Synthesize(ctx context.Context, req Request) (*Result, error) {
	if p.APIKey == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("elevenlabs API key not configured")}
	}
	if req.Text == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("empty text")}
	}
	if req.VoiceID == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("elevenlabs voice ID not configured")}
	}

	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	body, err := json.Marshal(buildElevenLabsPayload(req, model))
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}

	endpoint := strings.TrimRight(p.Endpoint, "/")
	if endpoint == "" {
		endpoint = defaultElevenLabsEndpoint
	}
	endpoint += "/" + url.PathEscape(req.VoiceID) + "/stream?output_format=mp3_44100_128"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}
	httpReq.Header.Set("xi-api-key", p.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	started := time.Now()
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, &Error{Class: classifyTransportError(ctx, err), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		class := ErrorClassClientError
		if resp.StatusCode >= 500 {
			class = ErrorClassServerError
		}
		return nil, &Error{
			Class: class,
			Err:   fmt.Errorf("elevenlabs tts status=%d body=%s", resp.StatusCode, string(respBody)),
		}
	}

	audio, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &Error{Class: ErrorClassReadBody, Err: err}
	}
	if len(audio) == 0 {
		return nil, &Error{Class: ErrorClassEmptyResponse, Err: errors.New("elevenlabs tts returned empty body")}
	}

	return &Result{
		Audio:     audio,
		Provider:  p.ProviderID(req),
		LatencyMs: time.Since(started).Milliseconds(),
	}, nil
}

func buildElevenLabsPayload(req Request, model string) map[string]any {
	payload := map[string]any{
		"text":     req.Text,
		"model_id": model,
	}
	if req.LanguageCode != "" && model != "eleven_multilingual_v2" {
		payload["language_code"] = strings.ToLower(strings.TrimSpace(req.LanguageCode))
	}
	if req.Speed > 0 {
		payload["voice_settings"] = map[string]float64{
			"stability":        0.5,
			"similarity_boost": 0.75,
			"speed":            max(0.7, min(req.Speed, 1.2)),
		}
	}
	return payload
}
