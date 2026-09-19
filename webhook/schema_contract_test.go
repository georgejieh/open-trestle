package webhook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type webhookSchemaDocument struct {
	ID                   string   `json:"$id"`
	Type                 string   `json:"type"`
	AdditionalProperties bool     `json:"additionalProperties"`
	Required             []string `json:"required"`
	Properties           map[string]struct {
		Const any `json:"const"`
	} `json:"properties"`
}

func TestVerifiedDeliverySchemaMatchesCanonicalRecordShape(t *testing.T) {
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"action":"opened"}`), time.UnixMilli(100))
	encoded, _ := EncodeVerifiedDelivery(delivery)
	path := filepath.Join("..", "schemas", "webhook", "verified-delivery-v1.schema.json")
	schemaBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema webhookSchemaDocument
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.ID == "" || schema.Type != "object" || schema.AdditionalProperties {
		t.Fatalf("schema=%#v", schema)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range schema.Required {
		if _, exists := record[key]; !exists {
			t.Fatalf("missing %q", key)
		}
	}
	for key := range record {
		if _, exists := schema.Properties[key]; !exists {
			t.Fatalf("undeclared %q", key)
		}
	}
	var contract any
	_ = json.Unmarshal(record["contract"], &contract)
	if !reflect.DeepEqual(contract, schema.Properties["contract"].Const) {
		t.Fatalf("contract=%v", contract)
	}
}
