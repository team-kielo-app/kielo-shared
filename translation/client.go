package translation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	modelsURL  string
	apiKey     string
	httpClient *http.Client
}

type batchRequest struct {
	Texts      []string `json:"texts"`
	SourceLang string   `json:"source_lang"`
	TargetLang string   `json:"target_lang"`
}

type batchResponse struct {
	Translations []string `json:"translations"`
}

func NewClient(modelsURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{modelsURL: strings.TrimRight(modelsURL, "/"), apiKey: apiKey, httpClient: httpClient}
}

func (c *Client) IsAvailable() bool {
	return c != nil && strings.TrimSpace(c.modelsURL) != ""
}

func (c *Client) Translate(ctx context.Context, text, sourceLang, targetLang string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	translations := c.TranslateBatch(ctx, []string{text}, sourceLang, targetLang)
	if len(translations) == 0 {
		return ""
	}
	return translations[0]
}

func (c *Client) TranslateBatch(ctx context.Context, texts []string, sourceLang, targetLang string) []string {
	if !c.IsAvailable() || len(texts) == 0 {
		return nil
	}
	payload, err := json.Marshal(batchRequest{Texts: texts, SourceLang: sourceLang, TargetLang: targetLang})
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.modelsURL+"/api/v1/translations", bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("X-Internal-API-Key", c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	if len(body.Translations) < len(texts) {
		result := make([]string, len(texts))
		copy(result, body.Translations)
		return result
	}
	return body.Translations
}

func (c *Client) URL() string {
	return fmt.Sprintf("%s/api/v1/translations", c.modelsURL)
}
