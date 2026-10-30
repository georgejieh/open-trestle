package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestRuntimePolicyV3SchemaPreservesLegacyContractsAndClosesProfile(t *testing.T) {
	for _, previous := range []struct{ name, digest string }{
		{"runtime-policy-v1.schema.json", "dff07bb537101767273b2d12a8d151681f44cd8a00fd88e7b4855e7006ccb964"},
		{"runtime-policy-v2.schema.json", "afc8701b9a26ef448e6e3ebb95d4c772b950103cfe79b928c25d2040ec2428ca"},
	} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", previous.name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(encoded)) != previous.digest {
			t.Fatalf("legacy schema changed: %s", previous.name)
		}
	}
	read := func(name string) map[string]any {
		t.Helper()
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", name))
		if err != nil {
			t.Fatal(err)
		}
		return schemaFixtureObject(t, encoded)
	}
	previous, current := read("runtime-policy-v2.schema.json"), read("runtime-policy-v3.schema.json")
	if current["$id"] != "urn:open-trestle:schema:runtime:policy:v3" || current["$schema"] != previous["$schema"] || current["type"] != "object" || current["additionalProperties"] != false || !reflect.DeepEqual(current["required"], previous["required"]) {
		t.Fatal("v3 root contract changed")
	}
	oldFields, fields := schemaFixtureMap(t, previous["properties"]), schemaFixtureMap(t, current["properties"])
	if len(fields) != len(oldFields) || !reflect.DeepEqual(fields["schema_version"], map[string]any{"const": float64(3)}) {
		t.Fatal("v3 version or fields")
	}
	for key, value := range oldFields {
		if key != "schema_version" && key != "connections" && key != "verification_route_record_identity" && !reflect.DeepEqual(value, fields[key]) {
			t.Fatalf("legacy field changed: %s", key)
		}
	}
	verifier := schemaFixtureMap(t, fields["verification_route_record_identity"])
	if verifier["description"] != "Exact inventory record grant for independent verification; brokered generation requires the v3 profile and its approved direct verifier." {
		t.Fatal("v3 verifier description does not cover brokered pair")
	}
	delete(verifier, "description")
	oldVerifier := schemaFixtureMap(t, oldFields["verification_route_record_identity"])
	delete(oldVerifier, "description")
	if !reflect.DeepEqual(verifier, oldVerifier) {
		t.Fatal("verifier grant constraint changed")
	}
	oldItems := schemaFixtureMap(t, schemaFixtureMap(t, oldFields["connections"])["items"])
	items := schemaFixtureMap(t, schemaFixtureMap(t, fields["connections"])["items"])
	if items["additionalProperties"] != false || !reflect.DeepEqual(items["required"], oldItems["required"]) {
		t.Fatal("connection closure changed")
	}
	oldConnections, connections := schemaFixtureMap(t, oldItems["properties"]), schemaFixtureMap(t, items["properties"])
	if len(connections) != len(oldConnections)+2 {
		t.Fatal("unexpected profile fields")
	}
	for key, value := range oldConnections {
		if !reflect.DeepEqual(value, connections[key]) {
			t.Fatalf("legacy connection field changed: %s", key)
		}
	}
	if !reflect.DeepEqual(connections["request_profile"], map[string]any{"const": "openrouter_zdr_chat_v1"}) {
		t.Fatal("profile not closed")
	}
	authority := schemaFixtureMap(t, connections["brokered_route_authority"])
	authorityFields := schemaFixtureMap(t, authority["properties"])
	assertExactSchemaFields(t, authority, authorityFields, "route_record_identity evidence_manifest_digest account_policy_identity tenant_id repository_id provider_slug valid_from valid_until")
	branches, ok := items["allOf"].([]any)
	oldBranches := oldItems["allOf"].([]any)
	if !ok || len(branches) != len(oldBranches)+1 || !reflect.DeepEqual(branches[0], oldBranches[0]) {
		t.Fatal("credential constraint changed")
	}
	profile := schemaFixtureMap(t, branches[len(branches)-1])
	condition := schemaFixtureMap(t, profile["if"])
	if !reflect.DeepEqual(condition["anyOf"], []any{map[string]any{"required": []any{"request_profile"}}, map[string]any{"required": []any{"brokered_route_authority"}}}) {
		t.Fatal("profile fields not jointly required")
	}
	then := schemaFixtureMap(t, profile["then"])
	required := schemaFixtureStrings(t, then["required"])
	sort.Strings(required)
	if !reflect.DeepEqual(required, []string{"brokered_route_authority", "credential_environment", "request_profile"}) || !reflect.DeepEqual(then["properties"], map[string]any{"implementation": map[string]any{"const": "openai_chat_completions"}, "credential_mode": map[string]any{"const": "bearer"}, "endpoint": map[string]any{"const": "https://openrouter.ai/api/v1"}}) {
		t.Fatal("profile endpoint or credential constraint changed")
	}
}
