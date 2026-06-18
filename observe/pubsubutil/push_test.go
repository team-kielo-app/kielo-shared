package pubsubutil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushBody_DecodesBase64DataAutomatically(t *testing.T) {
	// Google sends data as base64; Go's json package auto-decodes []byte fields.
	// Confirms callers can work with raw payload bytes after Unmarshal without
	// a manual base64.StdEncoding.DecodeString step.
	pubsubJSON := []byte(`{
		"message": {
			"data": "eyJtZWRpYV9pZCI6IjEyMyJ9",
			"attributes": {"event_type": "media.uploaded.v1"},
			"messageId": "987",
			"publishTime": "2026-04-27T00:00:00Z"
		},
		"subscription": "projects/p/subscriptions/s"
	}`)

	var body PushBody
	require.NoError(t, json.Unmarshal(pubsubJSON, &body))

	assert.Equal(t, []byte(`{"media_id":"123"}`), body.Message.Data)
	assert.Equal(t, "media.uploaded.v1", body.Message.Attributes[EventTypeAttribute])
	assert.Equal(t, "987", body.Message.MessageID)
	assert.Equal(t, "2026-04-27T00:00:00Z", body.Message.PublishTime)
	assert.Equal(t, "projects/p/subscriptions/s", body.Subscription)
}

func TestPushBody_HandlesEmptyMessage(t *testing.T) {
	// Pub/Sub admin tooling sometimes posts empty-payload messages to
	// validate the endpoint — these should decode without error and
	// produce an empty Data slice the handler can short-circuit on.
	pubsubJSON := []byte(`{
		"message": {"data": "", "messageId": "x", "publishTime": "t"},
		"subscription": "s"
	}`)

	var body PushBody
	require.NoError(t, json.Unmarshal(pubsubJSON, &body))
	assert.Empty(t, body.Message.Data)
}

func TestPushBody_PreservesArbitraryAttributes(t *testing.T) {
	pubsubJSON := []byte(`{
		"message": {
			"data": "e30=",
			"attributes": {
				"event_type": "user.profile.updated.v1",
				"learning_language_code": "sv",
				"trace_id": "abc123"
			}
		},
		"subscription": "s"
	}`)

	var body PushBody
	require.NoError(t, json.Unmarshal(pubsubJSON, &body))
	assert.Equal(t, "user.profile.updated.v1", body.Message.Attributes["event_type"])
	assert.Equal(t, "sv", body.Message.Attributes[LanguageAttribute])
	assert.Equal(t, "abc123", body.Message.Attributes["trace_id"])
}
