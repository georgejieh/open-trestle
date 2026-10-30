package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Structural checks only: native route tests exercise selector semantics.
func TestRouteReferenceV2SchemaPreservesHistoricalV1(t *testing.T) {
	oldBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "provider", "route-reference-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(oldBytes)); got != "1155817739cae282630cdd8474954ee16ea7a9059f90cbfff0b142c3b664cb34" {
		t.Fatalf("v1 route-reference schema bytes changed: %s", got)
	}
	newBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "provider", "route-reference-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	old, current := schemaFixtureObject(t, oldBytes), schemaFixtureObject(t, newBytes)
	if current["$id"] != "urn:open-trestle:schema:provider:route-reference:v2" || current["$schema"] != old["$schema"] || current["type"] != "object" || current["additionalProperties"] != false || !reflect.DeepEqual(current["required"], old["required"]) || !reflect.DeepEqual(current["properties"], old["properties"]) {
		t.Fatal("v2 changed the six-field route-reference wire shape")
	}
	prior, defs := schemaFixtureMap(t, old["$defs"]), schemaFixtureMap(t, current["$defs"])
	if len(defs) != len(prior) {
		t.Fatal("unexpected v2 definitions")
	}
	for key, value := range prior {
		if key != "model_id" && !reflect.DeepEqual(defs[key], value) {
			t.Fatalf("unchanged route field grammar changed: %s", key)
		}
	}
	model := schemaFixtureMap(t, defs["model_id"])
	if model["type"] != "string" || model["minLength"] != float64(1) || model["maxLength"] != float64(255) {
		t.Fatal("v2 model bounds changed")
	}
	branches, ok := model["anyOf"].([]any)
	if !ok || len(branches) != 2 || !reflect.DeepEqual(branches[0], prior["model_id"]) {
		t.Fatal("v2 did not retain the old model grammar as its first branch")
	}
	tagged := schemaFixtureMap(t, branches[1])
	if tagged["pattern"] == nil || tagged["not"] == nil {
		t.Fatal("tagged branch lacks bounded ASCII grammar constraints")
	}
	condition := schemaFixtureMap(t, current["if"])
	if !reflect.DeepEqual(condition, map[string]any{"properties": map[string]any{"model_id": map[string]any{"pattern": ":"}}, "required": []any{"model_id"}}) || !reflect.DeepEqual(current["then"], map[string]any{"properties": map[string]any{"model_version": map[string]any{"const": ""}}}) {
		t.Fatal("tagged model/version conflict constraint missing")
	}
}
