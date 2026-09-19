package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func encodedInventory(t *testing.T) []byte {
	t.Helper()
	value := routeInventoryWire{SchemaVersion: 1, Routes: []routeDefinitionWire{{Zone: "private_remote", ProviderID: "provider-a", AdapterID: "adapter-a", ConnectionID: "connection-a", ModelID: "model-a", ModelVersion: "2026-01", MaxContextTokens: 128000, MaxOutputTokens: 8192, Features: []string{"structured_output"}, ContentLogging: "disabled", PricingKnown: true, InputMicroUSDPerMillionTokens: 1000, OutputMicroUSDPerMillionTokens: 2000, Quality: "tier_3", RegistryRevision: 7, RegistryStatus: "approved", EvidenceManifestBase64: base64.StdEncoding.EncodeToString([]byte(`{"benchmark":"approved"}`)), OperationalRevision: 9, Health: "healthy", Quota: "available", PerformanceRevision: 11, LatencyKnown: true, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func TestDecodeRouteInventoryAcceptsStrictBoundedDocument(t *testing.T) {
	encoded := encodedInventory(t)
	var w routeInventoryWire
	if err := json.Unmarshal(encoded, &w); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRouteDefinition(w.Routes[0]); err != nil {
		t.Fatalf("definition: %v %#v", err, w.Routes[0])
	}
	if err := validateUniqueJSONKeys(encoded); err != nil {
		t.Fatalf("keys: %v", err)
	}
	inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(encoded))
	if err != nil || inventory.Validate() != nil || inventory.RegistryRevision() != 7 || inventory.PerformanceRevision() != 11 {
		t.Fatalf("inventory=(%#v,%v)", inventory, err)
	}
}
func TestDecodeRouteInventoryRejectsAmbiguousDocuments(t *testing.T) {
	valid := encodedInventory(t)
	tests := map[string][]byte{"duplicate": bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), "unknown": bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"surprise":true`), 1), "noncanonical key": bytes.Replace(valid, []byte(`"schema_version"`), []byte(`"SchemaVersion"`), 1), "trailing": append(append([]byte(nil), valid...), []byte(` {}`)...), "bad base64": bytes.Replace(valid, []byte(base64.StdEncoding.EncodeToString([]byte(`{"benchmark":"approved"}`))), []byte(`***`), 1)}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(document))
			if err == nil || inventory.Identity() != "" {
				t.Fatalf("inventory=(%#v,%v)", inventory, err)
			}
		})
	}
}
