package llm

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

// GeminiJSONProvider calls
// generativelanguage.googleapis.com/v1beta/models/<model>:generateContent
// and returns the model's text response. When `Request.ResponseSchema`
// is non-nil, the provider sets `responseMimeType=application/json`
// + `responseSchema` so Gemini enforces the schema and emits a JSON
// string the caller can `json.Unmarshal` into a typed Go struct.
type GeminiJSONProvider struct {
	APIKey       string
	HTTPClient   *http.Client
	Endpoint     string // override for tests; defaults to Gemini prod base URL
	DefaultModel string // applied when Request.Model is empty
}

// NewGeminiJSONProvider builds a provider with Gemini production
// defaults. Caller wires its own http.Client (timeouts, proxy,
// transport). Empty client gets a 30s default — caller-side
// timeouts override via ctx anyway.
func NewGeminiJSONProvider(apiKey string, client *http.Client) *GeminiJSONProvider {
	if client == nil {
		client = httputil.NewClient(30 * time.Second)
	}
	return &GeminiJSONProvider{
		APIKey:       apiKey,
		HTTPClient:   client,
		Endpoint:     "https://generativelanguage.googleapis.com/v1beta/models",
		DefaultModel: "gemini-3.1-flash-lite-preview",
	}
}

// ProviderID round-trips into Result.Provider so metrics can split
// by model version. Format: `gemini:<model>`.
func (p *GeminiJSONProvider) ProviderID(req Request) string {
	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}
	return "gemini:" + model
}

func (p *GeminiJSONProvider) Generate(ctx context.Context, req Request) (*Result, error) {
	if p.APIKey == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("gemini API key not configured")}
	}
	if req.Prompt == "" {
		return nil, &Error{Class: ErrorClassClientError, Err: errors.New("empty prompt")}
	}

	model := req.Model
	if model == "" {
		model = p.DefaultModel
	}

	body, err := json.Marshal(buildGeminiPayload(req))
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}

	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "https://generativelanguage.googleapis.com/v1beta/models"
	}
	endpoint = strings.TrimRight(endpoint, "/") + "/" + model + ":generateContent?key=" + url.QueryEscape(p.APIKey)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Class: ErrorClassMarshal, Err: err}
	}
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
			Err:   fmt.Errorf("gemini status=%d body=%s", resp.StatusCode, string(respBody)),
		}
	}

	respBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, &Error{Class: ErrorClassReadBody, Err: readErr}
	}
	rawText, decodeErr := decodeGeminiResponse(respBytes)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return &Result{
		RawText:   rawText,
		Provider:  p.ProviderID(req),
		LatencyMs: time.Since(started).Milliseconds(),
	}, nil
}

func buildGeminiPayload(req Request) map[string]any {
	generationConfig := map[string]any{}
	if req.ResponseSchema != nil {
		generationConfig["responseMimeType"] = "application/json"
		generationConfig["responseSchema"] = req.ResponseSchema
	} else if req.ResponseMimeType != "" {
		generationConfig["responseMimeType"] = req.ResponseMimeType
	}
	if req.Temperature != nil {
		generationConfig["temperature"] = *req.Temperature
	}

	payload := map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]any{{"text": req.Prompt}}},
		},
	}
	if req.SystemPrompt != "" {
		payload["system_instruction"] = map[string]any{
			"parts": []map[string]any{{"text": req.SystemPrompt}},
		}
	}
	if len(generationConfig) > 0 {
		payload["generationConfig"] = generationConfig
	}
	return payload
}

func decodeGeminiResponse(respBytes []byte) (string, error) {
	var decoded struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBytes, &decoded); err != nil {
		return "", &Error{Class: ErrorClassDecode, Err: err}
	}
	if len(decoded.Candidates) == 0 || len(decoded.Candidates[0].Content.Parts) == 0 {
		return "", &Error{Class: ErrorClassMissingPayload, Err: errors.New("gemini response had no candidates or parts")}
	}
	rawText := decoded.Candidates[0].Content.Parts[0].Text
	if rawText == "" {
		return "", &Error{Class: ErrorClassEmptyResponse, Err: errors.New("gemini returned empty text")}
	}
	return rawText, nil
}

// classifyTransportError mirrors the TTS seam's classifier so both
// seams' ErrorClass labels follow the same rules.
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
