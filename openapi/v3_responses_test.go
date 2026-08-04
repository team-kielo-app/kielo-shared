package openapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestMarshalJSONDocumentsTypedAcceptedResponseAlongsidePrimarySuccess(t *testing.T) {
	type readyResponse struct {
		ID string `json:"id"`
	}
	type pendingResponse struct {
		JobID string `json:"job_id"`
	}

	registry := NewRegistry("test-service", "Test Service", "test")
	registry.Record(http.MethodGet, "/api/v3/jobs/{job_id}", Route{
		Summary:          "Get or prepare a job",
		PathParams:       []ParamSpec{{Name: "job_id", In: "path", Type: "string", Required: true}},
		Response:         readyResponse{},
		AcceptedResponse: pendingResponse{},
	})

	encoded, err := registry.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal registry: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode registry: %v", err)
	}
	paths := document["paths"].(map[string]any)
	operation := paths["/api/v3/jobs/{job_id}"].(map[string]any)["get"].(map[string]any)
	responses := operation["responses"].(map[string]any)
	for _, status := range []string{"200", "202"} {
		response, ok := responses[status].(map[string]any)
		if !ok {
			t.Fatalf("response %s missing: %#v", status, responses)
		}
		content, ok := response["content"].(map[string]any)
		if !ok || content["application/json"] == nil {
			t.Fatalf("response %s missing typed JSON content: %#v", status, response)
		}
	}
}
