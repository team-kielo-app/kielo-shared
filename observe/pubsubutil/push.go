package pubsubutil

// PushBody is the canonical envelope wrapping a single Pub/Sub message
// in a push-subscription HTTP request. Mirrors Google's documented push
// payload shape:
//
//	{
//	  "message": {
//	    "data":        "<base64-encoded payload>",
//	    "attributes":  {"event_type": "...", "learning_language_code": "sv"},
//	    "messageId":   "...",
//	    "publishTime": "..."
//	  },
//	  "subscription": "projects/.../subscriptions/..."
//	}
//
// Go's encoding/json automatically base64-decodes []byte fields, so
// Message.Data holds the decoded payload bytes after json.Unmarshal —
// callers don't need to base64-decode manually.
//
// Replaces the verbatim struct that lived in every push-handler file
// across kielo-cms, kielo-content-service, kielo-user-service, and
// kielo-communications-service. Centralizes the shape so future Pub/Sub
// platform changes only need updating in one place.
type PushBody struct {
	Message struct {
		Data        []byte            `json:"data"`
		Attributes  map[string]string `json:"attributes"`
		MessageID   string            `json:"messageId"`
		PublishTime string            `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}
