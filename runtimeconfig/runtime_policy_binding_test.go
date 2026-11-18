package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func bindingInventoryDocument(t *testing.T) []byte {
	t.Helper()
	var wire routeInventoryWire
	if err := json.Unmarshal(encodedInventory(t), &wire); err != nil {
		t.Fatal(err)
	}
	first := wire.Routes[0]
	first.Zone = "local"
	first.RegistryStatus = "pending"
	first.Health = "unknown"
	first.Quota = "unknown"
	second := first
	second.AdapterID = "adapter-b"
	second.ConnectionID = "connection-b"
	second.ModelID = "model-b"
	second.ProviderID = "provider-b"
	wire.Routes = []routeDefinitionWire{first, second}
	return bindingMarshal(t, wire)
}

func bindingTemplate(t *testing.T) []byte {
	t.Helper()
	wire := runtimePolicyWire{
		SchemaVersion: 1, ReviewPolicyIdentity: strings.Repeat("a", 64),
		MinContextTokens: 32000, MinOutputTokens: 4096,
		RequiredFeatures: []string{"structured_output"}, Classification: "confidential",
		AllowedZones: []string{"local"}, ContentLoggingAllowed: false,
		EstimatedInputTokens: 8000, MaxOutputTokens: 4096, MaxCostMicroUSD: 100000,
		PreferredRouteRecordIdentities: []string{}, VerificationIndependence: "distinct_provider",
		PublicationMinimumSeverity: "medium", PublicationMaxInlineFindings: 17,
		PublicationMinimumIndependence: "distinct_provider", PublicationBlockOnInconclusive: true,
		Connections: []providerConnectionWire{
			{Implementation: "openai_responses", AdapterID: "adapter-b", Endpoint: "http://127.0.0.1:11435/v1", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_BIND_B"},
			{Implementation: "openai_responses", AdapterID: "adapter-a", Endpoint: "http://127.0.0.1:11434/v1", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_BIND_A"},
		},
	}
	return bindingMarshal(t, wire)
}

func bindingMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bindingInventory(t *testing.T, document []byte) RouteInventory {
	t.Helper()
	inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func bindingRecordIDs(inventory RouteInventory) map[string]string {
	ids := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		ids[reference.AdapterID()] = record.Identity()
	}
	return ids
}

func TestBindRuntimePolicyChecksStaticIndependence(t *testing.T) {
	for _, level := range []string{"distinct_route", "distinct_model", "distinct_provider"} {
		for _, separation := range []string{"route", "model", "version", "provider"} {
			t.Run(level+"/"+separation, func(t *testing.T) {
				var inventoryWire routeInventoryWire
				if err := json.Unmarshal(bindingInventoryDocument(t), &inventoryWire); err != nil {
					t.Fatal(err)
				}
				first := inventoryWire.Routes[0]
				second := first
				second.AdapterID = "adapter-b"
				second.ConnectionID = "connection-b"
				switch separation {
				case "model":
					second.ModelID = "model-b"
				case "version":
					second.ModelVersion = "version-b"
				case "provider":
					second.ProviderID = "provider-b"
				}
				inventoryWire.Routes = []routeDefinitionWire{first, second}
				inventory := bindingInventory(t, bindingMarshal(t, inventoryWire))
				var template runtimePolicyWire
				if err := json.Unmarshal(bindingTemplate(t), &template); err != nil {
					t.Fatal(err)
				}
				template.VerificationIndependence = level
				template.PublicationMinimumIndependence = level
				encoded, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, template), "adapter-a", "adapter-b")
				valid := level == "distinct_route" || level == "distinct_model" && separation != "route" || separation == "provider"
				if valid && err != nil || !valid && (err == nil || encoded != nil) {
					t.Fatalf("static independence valid=%v err=%v bytes=%d", valid, err, len(encoded))
				}
			})
		}
	}
}

func TestBindRuntimePolicyPreservesTemplateAndPendingInventory(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	ids := bindingRecordIDs(inventory)
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			var expected runtimePolicyWire
			if err := json.Unmarshal(bindingTemplate(t), &expected); err != nil {
				t.Fatal(err)
			}
			expected.SchemaVersion = version
			expected.PreferredRouteRecordIdentities = []string{ids["adapter-b"]}
			template := bindingMarshal(t, expected)
			before := append([]byte(nil), template...)
			encoded, err := bindRuntimePolicy(context.Background(), inventory, template, "adapter-a", "adapter-b")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
			if err != nil || policy.ValidateAgainstInventory(inventory) != nil || policy.InventoryIdentity() != inventory.Identity() || policy.VerificationRouteRecordIdentity() != ids["adapter-b"] {
				t.Fatalf("bound policy: %v", err)
			}
			pinned, ok := policy.Ranking().PinnedRoute()
			if !ok || pinned.AdapterID() != "adapter-a" {
				t.Fatal("generation route was not pinned")
			}
			var actual runtimePolicyWire
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			expected.SchemaVersion = 2
			expected.InventoryIdentity = inventory.Identity()
			expected.PinnedRouteRecordIdentity = ids["adapter-a"]
			verificationID := ids["adapter-b"]
			expected.VerificationRouteRecordIdentity = &verificationID
			if !reflect.DeepEqual(actual, expected) || !bytes.Equal(template, before) {
				t.Fatal("binding altered other template fields or source bytes")
			}
			for _, candidate := range inventory.Candidates() {
				if candidate.ResolvedRecord().RouteRegistryRecord().Status().String() != "pending" || candidate.OperationalState().Health().String() != "unknown" || candidate.OperationalState().Quota().String() != "unknown" {
					t.Fatal("binding changed route readiness")
				}
			}
		})
	}
}

func TestBindRuntimePolicyBindingPlaceholdersAndConflicts(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	ids := bindingRecordIDs(inventory)
	for _, key := range []string{"inventory_identity", "pinned_route_record_identity", "verification_route_record_identity"} {
		expected := map[string]string{"inventory_identity": inventory.Identity(), "pinned_route_record_identity": ids["adapter-a"], "verification_route_record_identity": ids["adapter-b"]}[key]
		for _, value := range []string{"", strings.Repeat("0", 64), expected, strings.Repeat("f", 64), "0", "invalid"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				var wire map[string]any
				if err := json.Unmarshal(bindingTemplate(t), &wire); err != nil {
					t.Fatal(err)
				}
				wire["schema_version"] = 2
				wire[key] = value
				encoded, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, wire), "adapter-a", "adapter-b")
				valid := value == "" || value == strings.Repeat("0", 64) || value == expected
				if valid && err != nil || !valid && (err == nil || encoded != nil) {
					t.Fatalf("binding placeholder valid=%v err=%v bytes=%d", valid, err, len(encoded))
				}
			})
		}
	}
}

func TestBindRuntimePolicyRefusesSelectionAndMalformedTemplates(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	valid := bindingTemplate(t)
	templates := map[string][]byte{
		"empty": nil, "null": []byte("null"), "malformed": []byte("{"),
		"oversize":            bytes.Repeat([]byte{' '}, 1<<20),
		"unknown":             bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
		"duplicate":           bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"trailing":            append(append([]byte(nil), valid...), []byte(" {}")...),
		"null binding":        bytes.Replace(valid, []byte(`"inventory_identity":""`), []byte(`"inventory_identity":null`), 1),
		"null constraint":     bytes.Replace(valid, []byte(`"content_logging_allowed":false`), []byte(`"content_logging_allowed":null`), 1),
		"null connection":     bytes.Replace(valid, []byte(`"connections":[{`), []byte(`"connections":[null,{`), 1),
		"v1 verifier field":   bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"verification_route_record_identity":""`), 1),
		"unknown version":     bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":3`), 1),
		"bad review identity": bytes.Replace(valid, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("0", 64)), 1),
		"invalid endpoint":    bytes.Replace(valid, []byte("http://127.0.0.1:11434/v1"), []byte("https://example.com/v1"), 1),
	}
	for name, template := range templates {
		t.Run(name, func(t *testing.T) {
			if encoded, err := bindRuntimePolicy(context.Background(), inventory, template, "adapter-a", "adapter-b"); err == nil || encoded != nil {
				t.Fatalf("invalid template accepted: err=%v bytes=%d", err, len(encoded))
			}
		})
	}
	for _, pair := range [][2]string{{"adapter-a", "adapter-a"}, {"missing", "adapter-b"}, {"adapter-a", "missing"}, {"", "adapter-b"}, {"adapter-a", ""}} {
		if encoded, err := bindRuntimePolicy(context.Background(), inventory, valid, pair[0], pair[1]); err == nil || encoded != nil {
			t.Fatalf("invalid adapter selection accepted: %v", pair)
		}
	}
	var wire routeInventoryWire
	if err := json.Unmarshal(bindingInventoryDocument(t), &wire); err != nil {
		t.Fatal(err)
	}
	ambiguous := wire
	third := wire.Routes[0]
	third.ModelID = "model-extra"
	ambiguous.Routes = append(append([]routeDefinitionWire(nil), wire.Routes...), third)
	nonlocal := wire
	nonlocal.Routes = append([]routeDefinitionWire(nil), wire.Routes...)
	nonlocal.Routes[0].Zone = "private_remote"
	for _, invalid := range []routeInventoryWire{ambiguous, nonlocal} {
		if encoded, err := bindRuntimePolicy(context.Background(), bindingInventory(t, bindingMarshal(t, invalid)), valid, "adapter-a", "adapter-b"); err == nil || encoded != nil {
			t.Fatal("ambiguous or nonlocal adapter selection accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if encoded, err := bindRuntimePolicy(ctx, inventory, valid, "adapter-a", "adapter-b"); err == nil || encoded != nil {
			t.Fatal("invalid context accepted")
		}
	}
	if encoded, err := bindRuntimePolicy(context.Background(), RouteInventory{}, valid, "adapter-a", "adapter-b"); err == nil || encoded != nil {
		t.Fatal("invalid inventory accepted")
	}
}

func TestBindProtectedRuntimePolicyReadsOnlyProtectedInputs(t *testing.T) {
	dir := t.TempDir()
	if err := setTestMode(t, dir, 0o700); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(dir, "routes.json")
	templatePath := filepath.Join(dir, "template.json")
	inventoryBytes, templateBytes := bindingInventoryDocument(t), bindingTemplate(t)
	for path, content := range map[string][]byte{inventoryPath: inventoryBytes, templatePath: templateBytes} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := BindProtectedRuntimePolicy(context.Background(), inventoryPath, templatePath, "adapter-a", "adapter-b")
	if err != nil || len(encoded) == 0 {
		t.Fatalf("protected binding: %v", err)
	}
	for path, expected := range map[string][]byte{inventoryPath: inventoryBytes, templatePath: templateBytes} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("binding changed input file")
		}
	}
	for _, paths := range [][2]string{{inventoryPath, inventoryPath}, {inventoryPath, ""}, {"", templatePath}, {inventoryPath, filepath.Join(dir, "missing")}} {
		if value, err := BindProtectedRuntimePolicy(context.Background(), paths[0], paths[1], "adapter-a", "adapter-b"); err == nil || value != nil {
			t.Fatal("invalid paths accepted")
		}
	}
	if err := setTestMode(t, templatePath, 0o666); err != nil {
		t.Fatal(err)
	}
	if value, err := BindProtectedRuntimePolicy(context.Background(), inventoryPath, templatePath, "adapter-a", "adapter-b"); err == nil || value != nil {
		t.Fatal("unsafe template accepted")
	}
}
