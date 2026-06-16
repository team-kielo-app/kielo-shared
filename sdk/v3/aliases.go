package sdkv3

// Hand-written companions for the generated models. These replace the
// oapi-codegen/runtime types (openapi_types.Date / .File) so the SDK depends
// only on stdlib + google/uuid — see scripts/deruntime-go-sdk.py. This file is
// NOT regenerated; keep it in sync with the types the generator would emit.

import (
	"strings"
	"time"
)

const dateLayout = "2006-01-02"

// Date is a date-only value (wire shape "2006-01-02"), replacing
// openapi_types.Date without pulling the oapi-codegen/runtime module.
type Date struct {
	time.Time
}

func (d Date) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Format(dateLayout) + `"`), nil
}

func (d *Date) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return err
	}
	d.Time = t
	return nil
}

// File replaces openapi_types.File for the rare request-model file field.
// The SDK is used for response typing, so a raw byte payload suffices; it
// marshals as base64 like any []byte.
type File = []byte
