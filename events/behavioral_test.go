package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contractFixturePath returns the repo-relative path to the shared
// wire-contract fixture. Both this Go test and the Python pydantic
// contract test in kielolearn-engine/tests/test_unit_behavioral_event_contract.py
// load THIS SAME FILE, so a divergence on either side trips its own
// test rather than silently 422-ing at runtime.
//
// The path walks out of kielo-shared/events/ → kielo-shared/ → repo
// root → tests/contract/fixtures/. If the repo is restructured, both
// tests need to update the relative path together; that's the point.
func contractFixturePath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "tests", "contract", "fixtures", "behavioral_engine_request.golden.json"))
	require.NoError(t, err)
	require.FileExists(t, p, "cross-language contract fixture missing")
	return p
}

func stringPtr(s string) *string { return &s }

func TestBehavioralEventRequest_JSONShape_OmitsOptionalFieldsWhenUnset(t *testing.T) {
	// The OAS shape marks item_id/item_type/properties optional. Pin
	// the wire output so a future "make these required" change must
	// also reach across to OAS + every downstream consumer.
	req := BehavioralEventRequest{
		EventType: "session_summary",
		Timestamp: "2026-01-01T00:00:00Z",
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	assert.JSONEq(t, `{"event_type":"session_summary","timestamp":"2026-01-01T00:00:00Z"}`, string(b))
}

func TestBehavioralEventRequest_JSONShape_OmitsUserIDByConstruction(t *testing.T) {
	// `user_id` MUST NOT appear in the body — it travels on the
	// X-User-ID header. Marshaling a fully-populated request must
	// not emit a user_id field even when the surrounding code path
	// has a user uuid in scope. This pins the OAS contract end-to-end.
	req := BehavioralEventRequest{
		EventType: "feature_usage",
		ItemID:    stringPtr("a-1"),
		ItemType:  stringPtr("BaseWord"),
		Properties: map[string]any{
			"feature": "lookup_word_daily",
		},
		Timestamp: "2026-01-01T00:00:00Z",
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &got))
	assert.NotContains(t, got, "user_id",
		"BehavioralEventRequest must not serialize user_id (header-sourced post-collapse)")
	assert.NotContains(t, got, "payload",
		"BehavioralEventRequest must not serialize a legacy payload key")
	assert.Contains(t, got, "event_type")
	assert.Contains(t, got, "item_id")
	assert.Contains(t, got, "item_type")
	assert.Contains(t, got, "properties")
	assert.Contains(t, got, "timestamp")
}

func TestNewRequest_DefaultsTimestampInRFC3339(t *testing.T) {
	req := NewRequest("item_saved", stringPtr("abc"), stringPtr("BaseWord"), nil)

	assert.Equal(t, "item_saved", req.EventType)
	assert.NotEmpty(t, req.Timestamp)
	_, err := time.Parse(time.RFC3339, req.Timestamp)
	require.NoError(t, err, "NewRequest must stamp an RFC3339 timestamp")
}

func TestBehavioralEventRequest_MatchesCrossLanguageContractFixture(t *testing.T) {
	// Pin that the Go canonical body MARSHALS to bytes that the
	// engine-side pydantic `BehavioralEventBase.model_validate_json`
	// accepts. The fixture file is also loaded by
	// kielolearn-engine/tests/test_unit_behavioral_event_contract.py
	// — same bytes, two languages.
	itemID := "22222222-2222-2222-2222-222222222222"
	itemType := "BaseWord"
	req := BehavioralEventRequest{
		EventType: "review_outcome",
		ItemID:    &itemID,
		ItemType:  &itemType,
		Properties: map[string]any{
			"outcome_correct":                   true,
			"klearn_proficiency_estimate_after": 0.75,
		},
		Timestamp: "2026-01-01T00:00:00Z",
	}

	got, err := json.Marshal(req)
	require.NoError(t, err)

	want, err := os.ReadFile(contractFixturePath(t))
	require.NoError(t, err)

	// assert.JSONEq tolerates key ordering — Go's json.Marshal sorts
	// map keys alphabetically while the fixture file groups them
	// semantically. We're pinning shape, not byte layout.
	assert.JSONEq(t, string(want), string(got),
		"BehavioralEventRequest output diverged from the shared contract fixture; "+
			"if intentional, update tests/contract/fixtures/behavioral_engine_request.golden.json "+
			"AND verify kielolearn-engine pydantic still accepts the new body.")
}

func TestUserIDHeader_IsTheCanonicalName(t *testing.T) {
	// Cheap pin: every caller MUST set this header — a typo
	// (`X-UserID`, `X-User-Id`, etc.) won't reach the engine
	// correctly. Keeping it as a string constant in this package
	// means callers import the same name.
	assert.Equal(t, "X-User-ID", UserIDHeader)
}
