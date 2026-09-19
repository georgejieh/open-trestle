package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupSchemasMatchCanonicalRecords(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	planEncoded, _ := EncodePlan(plan)
	key := pendingRequirement(t, plan)
	receipt, _ := newCheckReceipt(plan, key, setupDigest("checker"), CheckBlocked, setupDigest("evidence"), recoveryForKey(key), setupTime(1))
	receiptEncoded, _ := EncodeCheckReceipt(receipt)
	for _, test := range []struct {
		name, id string
		encoded  []byte
	}{{"setup-plan-v1.schema.json", "urn:open-trestle:schema:setup:plan:v1", planEncoded}, {"setup-check-receipt-v1.schema.json", "urn:open-trestle:schema:setup:check-receipt:v1", receiptEncoded}} {
		schemaBytes, err := os.ReadFile(filepath.Join("..", "schemas", "setup", test.name))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			ID         string                     `json:"$id"`
			Additional bool                       `json:"additionalProperties"`
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if json.Unmarshal(schemaBytes, &schema) != nil || schema.ID != test.id || schema.Additional {
			t.Fatalf("schema %s", test.name)
		}
		var record map[string]json.RawMessage
		if json.Unmarshal(test.encoded, &record) != nil {
			t.Fatal("record")
		}
		for _, key := range schema.Required {
			if _, ok := record[key]; !ok {
				t.Fatalf("%s missing %s", test.name, key)
			}
		}
		for key := range record {
			if _, ok := schema.Properties[key]; !ok {
				t.Fatalf("%s undeclared %s", test.name, key)
			}
		}
	}
}
