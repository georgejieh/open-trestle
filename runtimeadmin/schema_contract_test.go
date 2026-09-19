package runtimeadmin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeStatusSchemaMatchesCanonicalRecord(t *testing.T) {
	configuration, _ := NewConfiguration(validOptions())
	service, _ := NewService(configuration, nil)
	snapshot, _ := service.Snapshot("tenant-a", "repo-a", time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	encoded, _ := json.Marshal(snapshot)
	schemaBytes, err := os.ReadFile(filepath.Join("..", "schemas", "runtime", "runtime-status-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		ID         string                     `json:"$id"`
		Additional bool                       `json:"additionalProperties"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(schemaBytes, &schema) != nil || schema.ID != "urn:open-trestle:schema:runtime:status:v1" || schema.Additional {
		t.Fatal("invalid schema metadata")
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(encoded, &record) != nil {
		t.Fatal("invalid snapshot")
	}
	for _, name := range schema.Required {
		if _, ok := record[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	for name := range record {
		if _, ok := schema.Properties[name]; !ok {
			t.Fatalf("undeclared %s", name)
		}
	}
}
