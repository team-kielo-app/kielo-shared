// Package events defines the canonical wire type for behavioral
// telemetry events that flow between Kielo services. Post the
// round-12.x cross-service collapse there is ONE shape on the wire:
// the canonical OAS body. `user_id` is carried out-of-band via the
// `X-User-ID` request header, never in the body, so:
//
//   - Mobile clients (kielo-app) POST `/api/v3/events/behavioral` with
//     [BehavioralEventRequest]; the BFF stamps `X-User-ID` from JWT
//     claims after authentication and forwards verbatim.
//   - User-service / content-service / other backend services build
//     [BehavioralEventRequest] via [NewRequest] and POST it to the
//     engine with their own `X-User-ID` header.
//
// kielolearn-engine's pydantic [BehavioralEventBase] mirror validates
// the same shape, and the cross-language contract fixture at
// `tests/contract/fixtures/behavioral_engine_request.golden.json`
// pins Go marshaling against Python validation so drift on either
// side breaks its respective test instead of 422-ing in production.
//
// Pre-collapse this package also exported a `BehavioralEngineRequest`
// type with a nested `payload` map, plus a `ToEngineRequest` adapter
// that translated between shapes. Both are gone: there's no legacy
// shape on any wire anymore.
package events

import "time"

// BehavioralEventRequest is the canonical OAS BehavioralEventRequest
// shape — what every caller POSTs to `/api/v3/events/behavioral` and
// what kielolearn-engine's pydantic `BehavioralEventBase` validates
// against.
//
// `user_id` is intentionally NOT a field: callers stamp it on an
// `X-User-ID` header from authenticated context (JWT claims at the
// BFF, internal-API-key + caller-supplied at user-service /
// content-service). This prevents a body-only attacker from spoofing
// telemetry as another user.
//
// Field tags use pointers for the optional `item_id` / `item_type` so
// json marshaling omits them when unset — this matches the OAS
// schema (`required: [event_type, timestamp]`) and lets pydantic
// validators downstream distinguish "field not provided" from "field
// provided as empty string".
type BehavioralEventRequest struct {
	EventType  string         `json:"event_type"`
	ItemType   *string        `json:"item_type,omitempty"`
	ItemID     *string        `json:"item_id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	Timestamp  string         `json:"timestamp"`
}

// NewRequest constructs a [BehavioralEventRequest] with the timestamp
// stamped to time.Now() in RFC3339. The engine's timestamp field is
// non-optional, and callers occasionally omit it; centralizing the
// default here means every emitter (BFF forward, user-service fan-out,
// content-service direct) gets the same fallback policy.
//
// `itemID` / `itemType` accept the empty string as "not set" — they
// only get serialized to JSON when both pointer AND dereferenced value
// are non-empty. Same for `properties`: a nil map serializes as
// `omitempty`-absent rather than `null`.
func NewRequest(
	eventType string,
	itemID *string,
	itemType *string,
	properties map[string]any,
) BehavioralEventRequest {
	return BehavioralEventRequest{
		EventType:  eventType,
		ItemType:   itemType,
		ItemID:     itemID,
		Properties: properties,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
}

// UserIDHeader is the canonical HTTP header name carrying the
// authenticated `user_id` to the engine. Callers MUST set it on every
// request to `POST /events/behavioral`; the engine returns 422 without
// it.
const UserIDHeader = "X-User-ID"
