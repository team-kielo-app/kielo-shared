package media

import "time"

// Pub/Sub event-type routing keys for the media-lifecycle platform (set on
// attributes.event_type; see docs/architecture/media-lifecycle-platform.md and
// docs/architecture/pubsub-events.md). Payload structs below are the message
// bodies. Topic wiring + sharedevents registration live in the services.
//
// NOTE: the upload/processing pipeline events are NOT here — the live wire
// values are sharedevents.EventMediaProcessing ("media.processing.v1") and
// sharedevents.EventMediaProcessed ("media.processed.v1") in
// kielo-shared/events. This package used to duplicate them under a
// "kielo.media.*" spelling that no producer ever emitted; wiring a consumer to
// those constants silently never matched, so they were removed. GDPR erasure
// likewise has no dedicated request event: it is driven by the existing
// sharedevents "user.deleted.v1" (see MediaErasureRequestedEvent below).
const (
	EventMediaOwnerDeleted     = "kielo.media.owner_deleted.v1"
	EventMediaErasureCompleted = "kielo.media.erasure_completed.v1"
	EventMediaLifecycleTick    = "kielo.media.lifecycle_tick.v1"
)

// OwnerRef identifies the entity that owns a media asset.
type OwnerRef struct {
	Type string `json:"owner_type"`
	ID   string `json:"owner_id"`
}

// MediaUploadedEvent — emitted by upload-api when an upload is finalized.
type MediaUploadedEvent struct {
	MediaID    string    `json:"media_id"`
	Profile    string    `json:"profile"`
	Owner      OwnerRef  `json:"owner"`
	Role       string    `json:"role,omitempty"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// MediaProcessedEvent — emitted by the processor when variants are ready.
type MediaProcessedEvent struct {
	MediaID string `json:"media_id"`
	Profile string `json:"profile"`
	Status  string `json:"status"`
}

// OwnerDeletedEvent — an owning entity was deleted; cascade its attached media.
type OwnerDeletedEvent struct {
	Owner OwnerRef `json:"owner"`
}

// MediaErasureRequestedEvent — GDPR erasure for a data subject.
//
// There is NO new user-service event for this: erasure is driven by the
// EXISTING sharedevents "user.deleted.v1" (emitted on hard account deletion,
// which carries the deleted user_id). The lifecycle worker subscribes to that
// topic and calls Handler.HandleErasureRequested with the user_id. This struct
// is the internal media-domain representation the worker passes in.
type MediaErasureRequestedEvent struct {
	SubjectUserID string    `json:"subject_user_id"`
	RequestedAt   time.Time `json:"requested_at"`
}

// MediaErasureCompletedEvent — proof-of-erasure for compliance.
type MediaErasureCompletedEvent struct {
	SubjectUserID string    `json:"subject_user_id"`
	MediaCount    int       `json:"media_count"`
	CompletedAt   time.Time `json:"completed_at"`
}

// LifecycleTickEvent — scheduler heartbeat driving the reconciler.
type LifecycleTickEvent struct {
	Kind string `json:"kind"` // "reconcile" | "lookahead"
}
