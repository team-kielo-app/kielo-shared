package openapi

import (
	"reflect"
	"testing"

	"github.com/team-kielo-app/kielo-shared/openapi/internal/collidea"
	"github.com/team-kielo-app/kielo-shared/openapi/internal/collideb"
)

type collideHolder struct {
	A collidea.Morphology `json:"a"`
	B collideb.Morphology `json:"b"`
	C collideb.Same       `json:"c"`
	D collidea.Same       `json:"d"`
}

func refOf(t *testing.T, schema any) string {
	t.Helper()
	m := schema.(map[string]any)
	return m["$ref"].(string)
}

func TestSchemaNameCollisionQualifiedDeterministically(t *testing.T) {
	r := NewRegistry("t", "T", "v1")
	props := structSchema(reflect.TypeOf(collideHolder{}), r).(map[string]any)["properties"].(map[string]any)

	a, b := refOf(t, props["a"]), refOf(t, props["b"])
	if a != "#/components/schemas/Morphology" {
		t.Fatalf("first type keeps bare name, got %s", a)
	}
	if b != "#/components/schemas/MorphologyCollideb" {
		t.Fatalf("second type gets package-qualified name, got %s", b)
	}
	if _, ok := r.schemas["Morphology"]; !ok {
		t.Fatal("missing bare schema")
	}
	if _, ok := r.schemas["MorphologyCollideb"]; !ok {
		t.Fatal("missing qualified schema")
	}
}

func TestSchemaNameIdenticalStructuresShareOneSchema(t *testing.T) {
	r := NewRegistry("t", "T", "v1")
	props := structSchema(reflect.TypeOf(collideHolder{}), r).(map[string]any)["properties"].(map[string]any)
	if refOf(t, props["c"]) != refOf(t, props["d"]) {
		t.Fatalf("identical structures must share a schema: %v vs %v", props["c"], props["d"])
	}
	if _, ok := r.schemas["SameCollideb"]; ok {
		t.Fatal("duplicate identical schema should not be emitted")
	}
}

func TestSchemaNameSameTypeStable(t *testing.T) {
	r := NewRegistry("t", "T", "v1")
	x := refOf(t, fieldSchema(reflect.TypeOf(collideb.Morphology{}), r))
	y := refOf(t, fieldSchema(reflect.TypeOf(collideb.Morphology{}), r))
	if x != y || x != "#/components/schemas/Morphology" {
		t.Fatalf("same type must resolve to one name, got %s / %s", x, y)
	}
}

func TestSchemaRefUsesRegistryNames(t *testing.T) {
	r := NewRegistry("t", "T", "v1")
	r.collectSchema(collidea.Morphology{})
	r.collectSchema(collideb.Morphology{})
	if got := schemaRef(collideb.Morphology{}, r); got != "#/components/schemas/MorphologyCollideb" {
		t.Fatalf("schemaRef = %s", got)
	}
	if got := responseSchema(collideb.Morphology{}, r)["$ref"]; got != "#/components/schemas/MorphologyCollideb" {
		t.Fatalf("responseSchema = %v", got)
	}
}
