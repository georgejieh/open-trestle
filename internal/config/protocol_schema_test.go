package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPublishedProtocolSchemasHaveUniqueBoundedObjectContracts(t *testing.T) {
	root := filepath.Join("..", "..", "schemas")
	identities := map[string]string{}
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			return nil
		}
		count++
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema publishedProtocolSchema
		decoderErr := json.Unmarshal(encoded, &schema)
		if decoderErr != nil || schema.Dialect != "https://json-schema.org/draft/2020-12/schema" || !strings.HasPrefix(schema.Identity, "urn:open-trestle:schema:") || !schema.closedObjectContract() {
			t.Fatalf("schema %s has an invalid dialect, identity, or closed-object contract (decode error=%v)", path, decoderErr)
		}
		if previous, exists := identities[schema.Identity]; exists {
			t.Fatalf("schema identity %s reused by %s and %s", schema.Identity, previous, path)
		}
		identities[schema.Identity] = path
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 101 {
		t.Fatalf("published schema count=%d, want 101", count)
	}
}

// This inventory check is structural, not a JSON Schema validator. Each root
// alternative must retain the same closed-object checks as a standalone schema.
type publishedProtocolSchema struct {
	Dialect              string                     `json:"$schema"`
	Identity             string                     `json:"$id"`
	Type                 string                     `json:"type"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	Required             []string                   `json:"required"`
	Properties           map[string]json.RawMessage `json:"properties"`
	OneOf                json.RawMessage            `json:"oneOf"`
}

func (s publishedProtocolSchema) closedObjectContract() bool {
	// A closed root stays closed when oneOf adds further constraints. Preserve
	// that established pattern, including refinement-only alternatives.
	if s.closedObject() {
		return true
	}
	if len(s.OneOf) == 0 {
		return false
	}
	// Otherwise support a bounded choice of explicit closed objects. Do not
	// infer closure through references, nested choices or partial root shapes.
	if s.Type != "" || s.AdditionalProperties != nil || len(s.Required) != 0 || len(s.Properties) != 0 {
		return false
	}
	var alternatives []json.RawMessage
	if json.Unmarshal(s.OneOf, &alternatives) != nil || len(alternatives) < 2 || len(alternatives) > 8 {
		return false
	}
	for _, encoded := range alternatives {
		var alternative publishedProtocolSchema
		if json.Unmarshal(encoded, &alternative) != nil || !alternative.closedObject() {
			return false
		}
	}
	return true
}

func (s publishedProtocolSchema) closedObject() bool {
	return s.Type == "object" && s.AdditionalProperties != nil && !*s.AdditionalProperties && len(s.Required) > 0 && len(s.Properties) > 0
}

func TestPublishedProtocolSchemaClosedObjectAlternatives(t *testing.T) {
	closed := `{"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"a"}}}`
	other := strings.Replace(closed, `"const":"a"`, `"const":"b"`, 1)
	union := func(branches ...string) string { return `{"oneOf":[` + strings.Join(branches, ",") + `]}` }
	tests := []struct {
		name, schema string
		want         bool
	}{
		{"object", closed, true},
		{"closed alternatives", union(closed, other), true},
		{"open object", strings.Replace(closed, `"additionalProperties":false`, `"additionalProperties":true`, 1), false},
		{"open alternative", union(closed, `{"type":"object","required":["kind"],"properties":{"kind":{}}}`), false},
		{"scalar alternative", union(closed, `{"type":"string"}`), false},
		{"unconstrained alternative", union(closed, `{}`), false},
		{"reference alternative", union(closed, `{"$ref":"#/$defs/other"}`), false},
		{"no alternatives", union(), false},
		{"single alternative", union(closed), false},
		{"too many alternatives", union(closed, other, closed, other, closed, other, closed, other, closed), false},
		{"nested alternatives", union(closed, union(closed, other)), false},
		{"null alternatives", `{"oneOf":null}`, false},
		{"wrong alternatives type", `{"oneOf":{}}`, false},
		{"closed root with alternatives", strings.TrimSuffix(closed, "}") + `,"oneOf":[` + closed + "," + other + `]}`, true},
		{"closed root with refinements", strings.TrimSuffix(closed, "}") + `,"oneOf":[{"required":["kind"]},{"not":{"required":["kind"]}}]}`, true},
		{"partial root and alternatives", `{"type":"object","oneOf":[` + closed + "," + other + `]}`, false},
		{"eight closed alternatives", union(closed, other, closed, other, closed, other, closed, other), true},
		{"missing required", `{"type":"object","additionalProperties":false,"properties":{"kind":{}}}`, false},
		{"missing properties", `{"type":"object","additionalProperties":false,"required":["kind"]}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var schema publishedProtocolSchema
			err := json.Unmarshal([]byte(test.schema), &schema)
			got := err == nil && schema.closedObjectContract()
			if got != test.want {
				t.Fatalf("closed object contract=%v, want %v (decode error=%v)", got, test.want, err)
			}
		})
	}
}

// Versioned wire schemas preserve v1 bytes and describe only the v2 context-abstention shape.
func TestControlPlaneV2SchemasMatchContextFailureWireFixtures(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	files := []struct {
		name, oldDigest string
		newFields       []string
	}{
		{"review-task-completion", "d9a5c8a39f53b58216e135a37ee95d28297adb79f2753e7ead827ab5a4674e01", []string{"plan_identity", "task_identity", "output_kind"}},
		{"review-run-event", "8e466b0182bb3f6d16432244acd0b84ef0af5d73f4bc5f6e231c157183e07a26", []string{"output_kind"}},
		{"review-run-receipt", "eacffed4b254abba7785ceab06da144686b53986c78d9752e8b08f6aa2bd755c", nil},
	}
	for _, file := range files {
		t.Run(file.name, func(t *testing.T) {
			oldPath := filepath.Join("..", "..", "schemas", "controlplane", file.name+"-v1.schema.json")
			oldBytes, err := os.ReadFile(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(oldBytes)); got != file.oldDigest {
				t.Fatalf("v1 schema changed: %s", got)
			}
			old := schemaFixtureObject(t, oldBytes)
			newBytes, err := os.ReadFile(strings.TrimSuffix(oldPath, "-v1.schema.json") + "-v2.schema.json")
			if err != nil {
				t.Fatal(err)
			}
			current := schemaFixtureObject(t, newBytes)
			if current["$schema"] != old["$schema"] || current["$id"] != strings.Replace(old["$id"].(string), ":v1", ":v2", 1) || current["type"] != "object" || current["additionalProperties"] != false {
				t.Fatal("v2 dialect, identity, or root closure mismatch")
			}
			properties := schemaFixtureMap(t, current["properties"])
			oldProperties := schemaFixtureMap(t, old["properties"])
			if !reflect.DeepEqual(properties["contract"], oldProperties["contract"]) || !reflect.DeepEqual(properties["schema_version"], map[string]any{"const": float64(2)}) {
				t.Fatal("wire contract or version mismatch")
			}
			expected := make([]string, 0, len(oldProperties)+len(file.newFields))
			for key := range oldProperties {
				expected = append(expected, key)
			}
			expected = append(expected, file.newFields...)
			sort.Strings(expected)
			actual := make([]string, 0, len(properties))
			for key := range properties {
				actual = append(actual, key)
			}
			sort.Strings(actual)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("properties=%v, want %v", actual, expected)
			}
			for key, oldValue := range oldProperties {
				refined := key == "schema_version" || file.name == "review-task-completion" && (key == "status" || key == "output_identity" || key == "failure") || file.name == "review-run-event" && (key == "kind" || key == "output_identity" || key == "failure" || key == "task_key" || key == "task_identity" || key == "lease_token_identity" || key == "attempt" || key == "sequence" || key == "previous_identity" || key == "worker_identity" || key == "lease_expires_at_milliseconds") || file.name == "review-run-receipt" && key == "tasks"
				if !refined && !reflect.DeepEqual(properties[key], oldValue) {
					t.Fatalf("changed v1 property %s", key)
				}
			}
			oldRequired := schemaFixtureStrings(t, old["required"])
			newRequired := schemaFixtureStrings(t, current["required"])
			if file.name != "review-run-receipt" {
				oldRequired = append(oldRequired, file.newFields...)
			}
			sort.Strings(oldRequired)
			sort.Strings(newRequired)
			if !reflect.DeepEqual(newRequired, oldRequired) {
				t.Fatalf("required=%v, want %v", newRequired, oldRequired)
			}
			switch file.name {
			case "review-task-completion":
				for _, key := range []string{"plan_identity", "task_identity"} {
					if !reflect.DeepEqual(properties[key], properties["identity"]) {
						t.Fatalf("%s is not a nonzero digest", key)
					}
				}
				if !reflect.DeepEqual(properties["output_kind"], map[string]any{"const": "context_abstention"}) || !reflect.DeepEqual(properties["status"], map[string]any{"const": "failed"}) || !reflect.DeepEqual(properties["output_identity"], properties["identity"]) || !reflect.DeepEqual(properties["failure"], failedRunFailureSchema()) {
					t.Fatal("v2 completion admits a non-failed or empty-output fixture")
				}
			case "review-run-event":
				if !reflect.DeepEqual(properties["output_kind"], map[string]any{"const": "context_abstention"}) || !reflect.DeepEqual(properties["kind"], map[string]any{"const": "task_failed"}) || !reflect.DeepEqual(properties["output_identity"], properties["identity"]) || !reflect.DeepEqual(properties["failure"], failedRunFailureSchema()) || !reflect.DeepEqual(properties["task_identity"], properties["identity"]) || !reflect.DeepEqual(properties["lease_token_identity"], properties["identity"]) || !reflect.DeepEqual(properties["previous_identity"], properties["identity"]) || !reflect.DeepEqual(properties["worker_identity"], map[string]any{"const": ""}) || !reflect.DeepEqual(properties["lease_expires_at_milliseconds"], map[string]any{"const": float64(0)}) {
					t.Fatal("v2 event admits a non-failed or empty-output fixture")
				}
			case "review-run-receipt":
				tasks := schemaFixtureMap(t, properties["tasks"])
				oldTasks := schemaFixtureMap(t, oldProperties["tasks"])
				items := schemaFixtureMap(t, tasks["items"])
				oldItems := schemaFixtureMap(t, oldTasks["items"])
				fields := schemaFixtureMap(t, items["properties"])
				prior := schemaFixtureMap(t, oldItems["properties"])
				if items["additionalProperties"] != false || len(fields) != len(prior)+1 || !reflect.DeepEqual(fields["output_kind"], map[string]any{"const": "context_abstention"}) {
					t.Fatal("v2 task item is open or output kind is not closed")
				}
				for key, value := range prior {
					if !reflect.DeepEqual(fields[key], value) {
						t.Fatalf("v2 task changed prior field %s", key)
					}
				}
				if !reflect.DeepEqual(items["required"], oldItems["required"]) {
					t.Fatal("v2 ordinary task fields changed")
				}
				checkReceiptContextFailureRules(t, tasks, items, digest)
			}
		})
	}
}

func schemaFixtureObject(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	return object
}
func schemaFixtureMap(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("not a schema object: %T", value)
	}
	return object
}
func schemaFixtureStrings(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("not a string array: %T", value)
	}
	result := make([]string, len(values))
	for index, item := range values {
		var good bool
		result[index], good = item.(string)
		if !good {
			t.Fatal("non-string required field")
		}
	}
	return result
}
func failedRunFailureSchema() map[string]any {
	return map[string]any{"enum": []any{"transient", "resource_limit", "policy", "invalid_input", "canceled", "dependency", "internal"}}
}
func checkReceiptContextFailureRules(t *testing.T, tasks, items map[string]any, digest string) {
	t.Helper()
	// These fixture checks distinguish a v2 receipt from ordinary failed, succeeded,
	// or untyped failed-output task records without assuming all tasks failed.
	failure := map[string]any{"status": "failed", "kind": "assemble_context", "output_identity": digest, "output_kind": "context_abstention"}
	condition := schemaFixtureMap(t, tasks["contains"])
	match := schemaFixtureMap(t, condition["properties"])
	for key, value := range map[string]any{"status": "failed", "kind": "assemble_context", "output_kind": "context_abstention"} {
		if !reflect.DeepEqual(match[key], map[string]any{"const": value}) {
			t.Fatalf("v2 contains does not demand %s", key)
		}
		if failure[key] != value {
			t.Fatalf("fixture %s mismatch", key)
		}
	}
	if !reflect.DeepEqual(match["output_identity"], schemaFixtureMap(t, items["properties"])["task_identity"]) {
		t.Fatal("v2 receipt has no required failed-output digest")
	}
	if !reflect.DeepEqual(condition["required"], []any{"status", "kind", "output_identity", "output_kind"}) {
		t.Fatal("v2 receipt contains omits required fields")
	}
	allOf, ok := items["allOf"].([]any)
	if !ok || len(allOf) != 1 {
		t.Fatal("v2 receipt lacks task-kind conditional")
	}
	branch := schemaFixtureMap(t, allOf[0])
	if !reflect.DeepEqual(branch["if"], map[string]any{"properties": map[string]any{"status": map[string]any{"const": "failed"}, "output_identity": match["output_identity"]}, "required": []any{"status", "output_identity"}}) || !reflect.DeepEqual(branch["then"], map[string]any{"properties": map[string]any{"kind": map[string]any{"const": "assemble_context"}}, "required": []any{"output_kind"}}) || !reflect.DeepEqual(branch["else"], map[string]any{"not": map[string]any{"required": []any{"output_kind"}}}) {
		t.Fatal("v2 receipt does not require the marker only on failed context output tasks")
	}
}

func TestControlPlaneV3PreparedEventSchema(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "controlplane", "review-run-event-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	current := schemaFixtureObject(t, encoded)
	previous, err := os.ReadFile(filepath.Join("..", "..", "schemas", "controlplane", "review-run-event-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	prior := schemaFixtureObject(t, previous)
	if current["$id"] != "urn:open-trestle:schema:controlplane:review-run-event:v3" || current["additionalProperties"] != false {
		t.Fatal("v3 scope or closure")
	}
	properties := schemaFixtureMap(t, current["properties"])
	old := schemaFixtureMap(t, prior["properties"])
	if len(properties) != len(old)+1 || !reflect.DeepEqual(properties["contract"], old["contract"]) || !reflect.DeepEqual(properties["schema_version"], map[string]any{"const": float64(3)}) || !reflect.DeepEqual(properties["kind"], map[string]any{"const": "context_abstention_prepared"}) || !reflect.DeepEqual(properties["failure"], map[string]any{"enum": []any{"resource_limit", "policy"}}) || !reflect.DeepEqual(properties["retry_at_milliseconds"], map[string]any{"const": float64(0)}) || !reflect.DeepEqual(properties["output_kind"], map[string]any{"const": "context_abstention"}) {
		t.Fatal("v3 event structure mismatch")
	}
	artifact := schemaFixtureMap(t, properties["prepared_artifact"])
	if artifact["type"] != "string" || artifact["contentEncoding"] != "base64" || artifact["maxLength"] != float64(16777216) {
		t.Fatal("v3 artifact bound mismatch")
	}
	required := schemaFixtureStrings(t, current["required"])
	if !containsSchemaField(required, "prepared_artifact") || !containsSchemaField(required, "output_kind") {
		t.Fatal("v3 fields optional")
	}
}
func containsSchemaField(fields []string, name string) bool {
	for _, field := range fields {
		if field == name {
			return true
		}
	}
	return false
}
