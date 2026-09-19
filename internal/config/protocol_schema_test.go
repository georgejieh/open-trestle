package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if count != 83 {
		t.Fatalf("published schema count=%d, want 83", count)
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
