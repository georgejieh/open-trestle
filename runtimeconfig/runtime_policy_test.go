package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func runtimePolicyDocument(t *testing.T, inventory RouteInventory) []byte {
	t.Helper()
	record := inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	wire := runtimePolicyWire{SchemaVersion: 1, InventoryIdentity: inventory.Identity(), ReviewPolicyIdentity: strings.Repeat("a", 64), MinContextTokens: 32000, MinOutputTokens: 4096, RequiredFeatures: []string{"structured_output"}, Classification: "confidential", AllowedZones: []string{"private_remote"}, ContentLoggingAllowed: false, EstimatedInputTokens: 8000, MaxOutputTokens: 4096, MaxCostMicroUSD: 100000, PinnedRouteRecordIdentity: "", PreferredRouteRecordIdentities: []string{record}, VerificationIndependence: "distinct_provider", PublicationMinimumSeverity: "medium", PublicationMaxInlineFindings: 20, PublicationMinimumIndependence: "distinct_provider", PublicationBlockOnInconclusive: true, Connections: []providerConnectionWire{{Implementation: "openai_responses", AdapterID: "adapter-a", Endpoint: "https://api.openai.com/v1", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"}}}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func TestDecodeRuntimePolicyBindsInventoryPolicyAndCredentialAuthority(t *testing.T) {
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{routeDefinition(t, "model-a")})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(runtimePolicyDocument(t, inventory)), inventory)
	if err != nil || policy.Validate() != nil || policy.InventoryIdentity() != inventory.Identity() || policy.ReviewPolicyIdentity() != strings.Repeat("a", 64) || len(policy.Connections()) != 1 {
		t.Fatalf("policy=(%#v,%v)", policy, err)
	}
	connection := policy.Connections()[0]
	if connection.CredentialIdentity() == "" || connection.CredentialIdentity() == strings.Repeat("a", 64) || connection.CredentialEnvironment() != "OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY" {
		t.Fatal("credential authority was not derived from its reference")
	}
}
func TestDecodeRuntimePolicyRejectsCrossWiringAndAmbiguity(t *testing.T) {
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{routeDefinition(t, "model-a")})
	if err != nil {
		t.Fatal(err)
	}
	valid := runtimePolicyDocument(t, inventory)
	tests := map[string][]byte{"wrong inventory": bytes.Replace(valid, []byte(inventory.Identity()), []byte(strings.Repeat("b", 64)), 1), "zero policy": bytes.Replace(valid, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("0", 64)), 1), "bad credential reference": bytes.Replace(valid, []byte("OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"), []byte("HOME"), 1),
		"cross-authority credential reference": bytes.Replace(valid, []byte("OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"), []byte("OPEN_TRESTLE_API_TOKEN"), 1),
		"remote plaintext endpoint":            bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("http://example.com/v1"), 1),
		"remote localhost endpoint":            bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://localhost/v1"), 1),
		"remote loopback endpoint":             bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://127.0.0.1/v1"), 1),
		"endpoint user information":            bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://user:secret@example.com/v1"), 1),
		"endpoint query":                       bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://api.openai.com/v1?x=1"), 1),
		"noncanonical endpoint path":           bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://api.openai.com/v1//x"), 1),
		"empty endpoint port":                  bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://example.com:/v1"), 1),
		"noncanonical IPv6 endpoint":           bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://[0:0:0:0:0:0:0:1]/v1"), 1),
		"mapped IPv6 endpoint":                 bytes.Replace(valid, []byte("https://api.openai.com/v1"), []byte("https://[::ffff:c000:201]/v1"), 1),
		"unknown field":                        bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1), "duplicate field": bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory)
			if err == nil || policy.Identity() != "" {
				t.Fatalf("policy=(%#v,%v)", policy, err)
			}
		})
	}
}

func TestDecodeRuntimePolicyRejectsAmbiguousAdapterNamespace(t *testing.T) {
	first := routeDefinition(t, "model-a")
	second := routeDefinition(t, "model-b")
	route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-b", "adapter-a", "connection-b", "model-b", "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	second.Route = route
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{first, second})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(runtimePolicyDocument(t, inventory)), inventory)
	if err == nil || policy.Identity() != "" {
		t.Fatal("ambiguous adapter namespace accepted")
	}
}
