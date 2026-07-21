package stt

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

	sharedhttputil "github.com/team-kielo-app/kielo-shared/observe/httputil"
)

type DeepgramProvider struct {
	APIKey       string
	HTTPClient   *http.Client
	Endpoint     string
	DefaultModel string
}

func NewDeepgramProvider(apiKey string, client *http.Client) *DeepgramProvider {
	if client == nil {
		client = sharedhttputil.NewClient(45 * time.Second)
	}
	return &DeepgramProvider{
		APIKey:       apiKey,
		HTTPClient:   client,
		Endpoint:     "https://api.deepgram.com/v1/listen",
		DefaultModel: "nova-3",
	}
}

func (p *DeepgramProvider) Transcribe(ctx context.Context, req Request) (*Result, error) {
	if p.APIKey == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("Deepgram API key not configured")}
	}
	if len(req.Audio) == 0 {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("empty audio")}
	}
	if req.Language != "fi" && req.Language != "sv" {
		return nil, &Error{Class: ErrorClassClientError, Err: fmt.Errorf("unsupported language %q", req.Language)}
	}

	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "https://api.deepgram.com/v1/listen"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, &Error{Class: ErrorClassClientError, Err: err}
	}
	query := parsed.Query()
	query.Set("model", model)
	query.Set("language", req.Language)
	query.Set("smart_format", "true")
	query.Set("punctuate", "true")
	for _, keyterm := range req.Keyterms {
		if trimmed := strings.TrimSpace(keyterm); trimmed != "" {
			query.Add("keyterm", trimmed)
		}
	}
	parsed.RawQuery = query.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(req.Audio))
	if err != nil {
		return nil, &Error{Class: ErrorClassClientError, Err: err}
	}
	httpReq.Header.Set("Authorization", "Token "+p.APIKey)
	contentType := strings.TrimSpace(req.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	httpReq.Header.Set("Content-Type", contentType)

	started := time.Now()
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, &Error{Class: classifyTransportError(ctx, err), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		class := ErrorClassClientError
		if resp.StatusCode >= 500 {
			class = ErrorClassServerError
		}
		return nil, &Error{
			Class: class,
			Err:   fmt.Errorf("deepgram stt status=%d body=%s", resp.StatusCode, string(body)),
		}
	}

	var payload struct {
		Results struct {
			Channels []struct {
				DetectedLanguage string `json:"detected_language"`
				Alternatives     []struct {
					Transcript string  `json:"transcript"`
					Confidence float64 `json:"confidence"`
				} `json:"alternatives"`
			} `json:"channels"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, &Error{Class: ErrorClassDecode, Err: err}
	}
	if len(payload.Results.Channels) == 0 || len(payload.Results.Channels[0].Alternatives) == 0 {
		return nil, &Error{Class: ErrorClassEmptyResponse, Err: errors.New("deepgram returned no alternatives")}
	}

	channel := payload.Results.Channels[0]
	alternative := channel.Alternatives[0]
	alternative.Transcript = strings.TrimSpace(alternative.Transcript)
	if alternative.Transcript == "" {
		return nil, &Error{Class: ErrorClassEmptyResponse, Err: errors.New("deepgram detected no speech")}
	}
	language := channel.DetectedLanguage
	if language == "" {
		language = req.Language
	}
	return &Result{
		Transcript: alternative.Transcript,
		Confidence: alternative.Confidence,
		Language:   language,
		Provider:   "deepgram:" + model,
		LatencyMs:  time.Since(started).Milliseconds(),
	}, nil
}

func classifyTransportError(ctx context.Context, err error) ErrorClass {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrorClassTimeout
	}
	if strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(err.Error(), "deadline exceeded") {
		return ErrorClassTimeout
	}
	return ErrorClassConnection
}
