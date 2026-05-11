package tts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/team-kielo-app/kielo-shared/observe/httputil"
)

// OpenAITTSProvider calls the OpenAI /v1/audio/speech endpoint.
// Stateless beyond the injected http.Client + API key. Caller-side
// concerns (cache, breaker, voice normalization) stay outside the
// provider per the seam scope rules in types.go.
type OpenAITTSProvider struct {
	APIKey       string
	HTTPClient   *http.Client
	Endpoint     string // override for tests; defaults to OpenAI prod
	DefaultModel string // applied when Request.Model is empty
}

// NewOpenAITTSProvider builds a provider with sensible defaults.
// Callers wire their own http.Client with timeouts / proxy so the
// seam doesn't leak transport policy.
func NewOpenAITTSProvider(apiKey string, client *http.Client) *OpenAITTSProvider {
	if client == nil {
		client = httputil.NewClient(30 * time.Second)
	}
	return &OpenAITTSProvider{
		APIKey:       apiKey,
		HTTPClient:   client,
		Endpoint:     "https://api.openai.com/v1/audio/speech",
		DefaultModel: "tts-1",
	}
}

// ProviderID round-trips into Result.Provider so metrics can split
// by model version. Format: `openai-tts:<model>`.
func (p *OpenAITTSProvider) ProviderID(req Request) string {
	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	return "openai-tts:" + model
}

func (p *OpenAITTSProvider) Synthesize(ctx context.Context, req Request) (*Result, error) {
	if p.APIKey == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("OpenAI API key not configured")}
	}
	if req.Text == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("empty text")}
	}

	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	payload := map[string]any{
		"model":           model,
		"voice":           req.VoiceID,
		"input":           req.Text,
		"response_format": "mp3",
	}
	if req.Speed > 0 {
		payload["speed"] = req.Speed
	}
	// gpt-4o-mini-tts accepts a `instructions` field for stylistic
	// hints; older `tts-1*` models reject it.
	if req.Instructions != "" && model == "gpt-4o-mini-tts" {
		payload["instructions"] = req.Instructions
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}

	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/audio/speech"
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	started := time.Now()
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, &Error{Class: classifyTransportError(ctx, err), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		class := ErrorClassClientError
		if resp.StatusCode >= 500 {
			class = ErrorClassServerError
		}
		return nil, &Error{
			Class: class,
			Err:   fmt.Errorf("openai tts status=%d body=%s", resp.StatusCode, string(respBody)),
		}
	}

	audio, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &Error{Class: ErrorClassReadBody, Err: err}
	}
	if len(audio) == 0 {
		return nil, &Error{Class: ErrorClassEmptyResponse, Err: errors.New("openai tts returned empty body")}
	}

	return &Result{
		Audio:     audio,
		Provider:  p.ProviderID(req),
		LatencyMs: time.Since(started).Milliseconds(),
	}, nil
}

// classifyTransportError maps a transport-layer error from
// http.Client.Do into a stable ErrorClass for metric labels and
// caller-side retry policies.
func classifyTransportError(ctx context.Context, err error) ErrorClass {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrorClassTimeout
	}
	msg := err.Error()
	if strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "deadline exceeded") {
		return ErrorClassTimeout
	}
	return ErrorClassConnection
}
