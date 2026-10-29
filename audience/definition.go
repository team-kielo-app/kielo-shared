package audience

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// Version is the only definition version the compiler understands.
	Version = 1
	// MaxConditions bounds one definition.
	MaxConditions = 20
	// MaxDays bounds every "N days" value.
	MaxDays = 3650
	// MaxLanguages bounds a language list.
	MaxLanguages = 50
)

// Condition is one rule of a definition.
type Condition struct {
	Field string          `json:"field"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value"`
}

// Definition is a stored audience: all conditions must hold.
type Definition struct {
	Version int         `json:"version"`
	All     []Condition `json:"all"`
}

// Parse decodes and validates a stored definition.
func Parse(raw []byte) (Definition, error) {
	var d Definition
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Definition{}, fmt.Errorf("this audience could not be read: %w", err)
	}
	if dec.More() {
		return Definition{}, errors.New("this audience could not be read: extra data after the definition")
	}
	if err := d.Validate(); err != nil {
		return Definition{}, err
	}
	return d, nil
}

// Validate reports the first problem an admin can fix.
func (d Definition) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("this audience has version %d; only version %d is supported", d.Version, Version)
	}
	if len(d.All) > MaxConditions {
		return fmt.Errorf("an audience can have at most %d conditions; this one has %d", MaxConditions, len(d.All))
	}
	for i, c := range d.All {
		if _, err := c.compile(); err != nil {
			return fmt.Errorf("condition %d: %w", i+1, err)
		}
	}
	return nil
}

func (c Condition) compile() (compiled, error) {
	def, ok := fieldDefs[c.Field]
	if !ok {
		return nil, fmt.Errorf("%q is not something an audience can filter on", c.Field)
	}
	if !def.hasOp(c.Op) {
		return nil, fmt.Errorf("%s cannot be combined with %q; use %s", def.spec.Label, c.Op, def.opList())
	}
	return def.parse(def, c.Op, c.Value)
}

func (f fieldDef) hasOp(op string) bool {
	for _, o := range f.spec.Ops {
		if o.Op == op {
			return true
		}
	}
	return false
}

func (f fieldDef) opList() string {
	ops := make([]string, len(f.spec.Ops))
	for i, o := range f.spec.Ops {
		ops[i] = fmt.Sprintf("%q", o.Op)
	}
	return strings.Join(ops, " or ")
}

func decodeStrict(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("a value is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected extra data")
	}
	return nil
}
