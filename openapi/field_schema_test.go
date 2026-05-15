package openapi

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestFieldSchema_WireTypes pins the OpenAPI mapping for Go types whose
// JSON wire format does not match their reflected structure.
//
// Without these explicit mappings, reflect.Type renders:
//   - uuid.UUID ([16]byte)   → {"type":"array","items":{"type":"integer"}}
//   - time.Time (struct)     → {"type":"object","properties":{}}
//   - json.RawMessage ([]byte) → {"type":"array","items":{"type":"integer"}}
//
// All three are wire-incorrect and have, in the past, corrupted the
// generated TypeScript SDKs (admin-ui, kielo-app). This test prevents
// regressions: removing or weakening the mapping in v3.go fails here.
func TestFieldSchema_WireTypes(t *testing.T) {
	r := &Registry{schemas: map[string]any{}}

	cases := []struct {
		name string
		in   reflect.Type
		want map[string]any
	}{
		{
			name: "uuid.UUID renders as string with format uuid",
			in:   reflect.TypeOf(uuid.UUID{}),
			want: map[string]any{"type": "string", "format": "uuid"},
		},
		{
			name: "pointer to uuid.UUID renders the same",
			in:   reflect.TypeOf((*uuid.UUID)(nil)),
			want: map[string]any{"type": "string", "format": "uuid"},
		},
		{
			name: "time.Time renders as string with format date-time",
			in:   reflect.TypeOf(time.Time{}),
			want: map[string]any{"type": "string", "format": "date-time"},
		},
		{
			name: "pointer to time.Time renders the same",
			in:   reflect.TypeOf((*time.Time)(nil)),
			want: map[string]any{"type": "string", "format": "date-time"},
		},
		{
			name: "json.RawMessage renders as free-form value",
			in:   reflect.TypeOf(json.RawMessage{}),
			want: map[string]any{},
		},
		{
			// `any` / `interface{}` MUST render as free-form (empty
			// schema) so consumers see the value as `unknown` rather
			// than the default `type: object` (which the @hey-api SDK
			// codegen interprets as Record<string, unknown> — and then
			// for `map[string]any` doubles up into a nested record).
			// Closes round-22 regression in CommsCreateJobRequest.data.
			name: "interface{} renders as free-form value",
			in:   reflect.TypeOf((*any)(nil)).Elem(),
			want: map[string]any{},
		},
		{
			// `map[string]any` renders with additionalProperties: true
			// (open-ended record). Without this, the Interface fallback
			// would emit additionalProperties: {type: object}, which
			// hey-api flattens to Record<string, Record<string, unknown>>
			// — a value-shape that has no Go counterpart.
			name: "map[string]any renders as object with additionalProperties: true",
			in:   reflect.TypeOf(map[string]any{}),
			want: map[string]any{"type": "object", "additionalProperties": true},
		},
		{
			// `map[string]string` stays in the typed branch: additionalProperties
			// emits the element schema as before.
			name: "map[string]string renders typed additionalProperties",
			in:   reflect.TypeOf(map[string]string{}),
			want: map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fieldSchema(tc.in, r)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("fieldSchema(%v) = %#v; want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestStructSchema_PointerFieldsNotRequired pins the policy: a struct
// field declared as `*T` (pointer) is NOT included in the schema's
// `required` array, even when the JSON tag has no `omitempty`.
// Rationale: a nil pointer marshals as JSON `null` and a missing field
// decodes back to nil, so the receiver doesn't observe whether the
// sender omitted the field or sent it as null. Marking it required
// forces TS consumers to invent placeholder values for fields the
// server treats as optional.
func TestStructSchema_PointerFieldsNotRequired(t *testing.T) {
	type sample struct {
		Required    string  `json:"required"`
		PointerOpt  *string `json:"pointer_opt"`
		ExplicitOpt string  `json:"explicit_opt,omitempty"`
	}

	r := &Registry{schemas: map[string]any{}}
	got := structSchema(reflect.TypeOf(sample{}), r).(map[string]any)
	required, _ := got["required"].([]string)

	wantRequired := map[string]bool{"required": true}
	for _, name := range required {
		if !wantRequired[name] {
			t.Errorf("unexpected field %q in required[]; want only %v", name, wantRequired)
		}
		delete(wantRequired, name)
	}
	for name := range wantRequired {
		t.Errorf("missing field %q from required[]", name)
	}
}

// TestStructSchema_WireTypesInFields exercises the full struct path: a
// struct containing a uuid.UUID + *uuid.UUID + time.Time + *time.Time +
// json.RawMessage must render every field with the correct wire shape,
// not the reflect-default array/object representations.
func TestStructSchema_WireTypesInFields(t *testing.T) {
	type sampleEntry struct {
		ID          uuid.UUID       `json:"id"`
		ParentID    *uuid.UUID      `json:"parent_id,omitempty"`
		CreatedAt   time.Time       `json:"created_at"`
		PublishedAt *time.Time      `json:"published_at,omitempty"`
		Payload     json.RawMessage `json:"payload,omitempty"`
	}

	r := &Registry{schemas: map[string]any{}}
	got := structSchema(reflect.TypeOf(sampleEntry{}), r).(map[string]any)
	props := got["properties"].(map[string]any)

	want := map[string]map[string]any{
		"id":           {"type": "string", "format": "uuid"},
		"parent_id":    {"type": "string", "format": "uuid"},
		"created_at":   {"type": "string", "format": "date-time"},
		"published_at": {"type": "string", "format": "date-time"},
		"payload":      {},
	}

	for name, expected := range want {
		actual, ok := props[name]
		if !ok {
			t.Fatalf("missing field %q in schema", name)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("field %q: got %#v; want %#v", name, actual, expected)
		}
	}
}
