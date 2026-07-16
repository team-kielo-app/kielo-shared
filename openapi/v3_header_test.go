package openapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOperationDocEmitsRequiredHeaderParameter(t *testing.T) {
	registry := NewRegistry("test", "Test", "v1")
	op := registry.operationDoc(routeEntry{
		method: "POST",
		path:   "/api/v3/notifications",
		headerParams: []paramSpec{{
			Name:        "Idempotency-Key",
			In:          "header",
			Type:        "string",
			Required:    true,
			Description: "Stable semantic key.",
		}},
	})

	params, ok := op["parameters"].([]any)
	require.True(t, ok)
	require.Len(t, params, 1)
	param, ok := params[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "Idempotency-Key", param["name"])
	require.Equal(t, "header", param["in"])
	require.Equal(t, true, param["required"])
}

func TestOperationDocEmitsExplicitAcceptedStatus(t *testing.T) {
	registry := NewRegistry("test", "Test", "v1")
	op := registry.operationDoc(routeEntry{
		method:        "POST",
		path:          "/api/v3/notifications",
		successStatus: 202,
	})

	responses, ok := op["responses"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, responses, "202")
	require.NotContains(t, responses, "204")
	require.Equal(t, map[string]any{"description": "Accepted"}, responses["202"])
}
