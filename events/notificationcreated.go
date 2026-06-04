package events

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// NotificationCreatedEvent is the canonical wire shape for the
// `user.notification.created.v1` Pub/Sub event. Pre-Sweep-Bucket-4
// this struct was duplicated byte-equivalent between:
//   - kielo-communications-service/internal/pubsub/notification_events.go
//   - kielo-user-service/internal/models/notification.go
//
// Both producers + consumers serialized/deserialized through identical
// fields with identical JSON tags. A field rename on one side without
// the other was a Sweep G envelope-drift class waiting to fire.
//
// Sweep post-ZT-followup-docker Bucket 4 (2026-06-04): lifted to
// kielo-shared/events with a Validate() method preserved on the struct
// so consumers can run the same validation logic without redeclaring.
// Cross-language parity test pinned in tests/contract/notification_
// created_event_contract_test.go.
//
// Closes docs/architecture/notification-system-design.md §5 Tier-1A #4.
type NotificationCreatedEvent struct {
	NotificationID uuid.UUID      `json:"notification_id"`
	UserID         uuid.UUID      `json:"user_id"`
	Type           string         `json:"type"`
	Title          string         `json:"title"`
	Body           string         `json:"body"`
	Data           map[string]any `json:"data"`
	CreatedAt      time.Time      `json:"created_at"`
}

// Validate returns true when the event has the minimum required fields.
// Mirrors the pre-Bucket-4 validation logic from
// kielo-user-service/internal/models/notification.go (the strictest
// of the 2 pre-lift implementations — comms-service had no Validate
// method declared on the struct). Preserves observable behavior: a
// notification with empty Body would have been rejected by user-
// service's consumer pre-lift and continues to be rejected post-lift.
//
// Sweep post-ZT-followup-docker Bucket 4 (2026-06-04).
func (e *NotificationCreatedEvent) Validate() bool {
	if e == nil {
		return false
	}
	return e.NotificationID != uuid.Nil &&
		e.UserID != uuid.Nil &&
		strings.TrimSpace(e.Type) != "" &&
		strings.TrimSpace(e.Title) != "" &&
		strings.TrimSpace(e.Body) != ""
}
