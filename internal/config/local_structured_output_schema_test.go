package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func TestRuntimePolicyV6SchemaGenericLocalStructuredOutput(t *testing.T) {
	read := func(version int) map[string]any {
		t.Helper()
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", fmt.Sprintf("runtime-policy-v%d.schema.json", version)))
		if err != nil {
			t.Fatal(err)
		}
		return schemaFixtureObject(t, encoded)
	}
	current, prior := read(6), read(2)
	if current["$id"] != "urn:open-trestle:schema:runtime:policy:v6" || current["$schema"] != prior["$schema"] || current["type"] != "object" || current["additionalProperties"] != false || !reflect.DeepEqual(current["required"], prior["required"]) {
		t.Fatal("v6 root identity or closure")
	}
	fields, oldFields := schemaFixtureMap(t, current["properties"]), schemaFixtureMap(t, prior["properties"])
	if len(fields) != len(oldFields) || !reflect.DeepEqual(fields["schema_version"], map[string]any{"const": float64(6)}) {
		t.Fatal("v6 version or root fields")
	}
	for key, value := range oldFields {
		if key != "schema_version" && key != "connections" && !reflect.DeepEqual(fields[key], value) {
			t.Fatalf("changed generic property %s", key)
		}
	}
	items := schemaFixtureMap(t, schemaFixtureMap(t, fields["connections"])["items"])
	oldItems := schemaFixtureMap(t, schemaFixtureMap(t, oldFields["connections"])["items"])
	props, oldProps := schemaFixtureMap(t, items["properties"]), schemaFixtureMap(t, oldItems["properties"])
	if items["additionalProperties"] != false || !reflect.DeepEqual(items["required"], oldItems["required"]) || len(props) != len(oldProps)+1 {
		t.Fatal("v6 connection closure or fields")
	}
	for key, value := range oldProps {
		if !reflect.DeepEqual(props[key], value) {
			t.Fatalf("changed generic connection property %s", key)
		}
	}
	option := schemaFixtureMap(t, props["local_structured_output"])
	if option["type"] != "boolean" || len(option) != 2 || containsSchemaField(schemaFixtureStrings(t, items["required"]), "local_structured_output") {
		t.Fatal("option not optional boolean")
	}
	for _, version := range []int{1, 2, 3, 4} {
		historical := read(version)
		connections := schemaFixtureMap(t, schemaFixtureMap(t, schemaFixtureMap(t, historical["properties"])["connections"])["items"])
		if schemaFixtureMap(t, connections["properties"])["local_structured_output"] != nil {
			t.Fatalf("v%d permits option", version)
		}
	}
	branches := items["allOf"].([]any)
	oldBranches := oldItems["allOf"].([]any)
	if len(branches) != len(oldBranches)+1 || !reflect.DeepEqual(branches[0], oldBranches[0]) {
		t.Fatal("credential rule changed")
	}
	branch := schemaFixtureMap(t, branches[1])
	if !reflect.DeepEqual(branch["if"], map[string]any{"properties": map[string]any{"local_structured_output": map[string]any{"const": true}}, "required": []any{"local_structured_output"}}) {
		t.Fatal("option conditional")
	}
	then := schemaFixtureMap(t, branch["then"])
	constraints := schemaFixtureMap(t, then["properties"])
	if !reflect.DeepEqual(constraints["implementation"], map[string]any{"const": "openai_chat_completions"}) || len(constraints) != 2 {
		t.Fatal("option implementation restriction")
	}
	endpoint := schemaFixtureMap(t, constraints["endpoint"])
	pattern := regexp.MustCompile(endpoint["pattern"].(string))
	for _, fixture := range []struct {
		endpoint string
		want     bool
	}{{"http://127.0.0.1:11434/v1", true}, {"https://127.2.3.4/v1", true}, {"http://[::1]:11434/v1", true}, {"http://localhost:11434/v1", false}, {"https://api.example.test/v1", false}, {"http://127.0.0.1.example.test/v1", false}} {
		if pattern.MatchString(fixture.endpoint) != fixture.want {
			t.Fatalf("option endpoint %s", fixture.endpoint)
		}
	}
	for _, forbidden := range []string{"request_profile", "brokered_route_authority", "opencode_go_authority", "opencode_console_authority"} {
		if props[forbidden] != nil {
			t.Fatalf("v6 generic schema permits %s", forbidden)
		}
	}
	if !reflect.DeepEqual(schemaFixtureMap(t, fields["allowed_zones"]), schemaFixtureMap(t, oldFields["allowed_zones"])) {
		t.Fatal("zone constraints changed")
	}
}

func TestRuntimePolicyV6SchemaInventoryAndReferences(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol-contracts.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile("(?m)^- `schemas/runtime/runtime-policy-v6.schema.json`$").Match(encoded) {
		t.Fatal("v6 absent from published schema inventory")
	}
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", "runtime-policy-v6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema := schemaFixtureObject(t, schemaBytes)
	var walk func(any)
	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if reference, ok := node["$ref"].(string); ok {
				t.Fatalf("generic standalone schema has unexpected reference %s", reference)
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(schema)
}
