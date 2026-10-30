package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRuntimePolicyV4SchemaPreservesLegacyAndClosesGoProfile(t *testing.T) {
	for _, previous := range []struct{ name, digest string }{
		{"runtime-policy-v1.schema.json", "dff07bb537101767273b2d12a8d151681f44cd8a00fd88e7b4855e7006ccb964"},
		{"runtime-policy-v2.schema.json", "afc8701b9a26ef448e6e3ebb95d4c772b950103cfe79b928c25d2040ec2428ca"},
		{"runtime-policy-v3.schema.json", "4e8b7ef9faaabbb678c03134afb05c8c51c42602b7149cd16892f2fc1a51e6ee"},
	} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", previous.name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(encoded)) != previous.digest {
			t.Fatalf("published schema changed: %s", previous.name)
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
	previous, current := read("runtime-policy-v3.schema.json"), read("runtime-policy-v4.schema.json")
	if current["$id"] != "urn:open-trestle:schema:runtime:policy:v4" || current["$schema"] != previous["$schema"] || current["type"] != "object" || current["additionalProperties"] != false || !reflect.DeepEqual(current["required"], previous["required"]) {
		t.Fatal("v4 root identity, closure or required fields")
	}
	oldFields, fields := schemaFixtureMap(t, previous["properties"]), schemaFixtureMap(t, current["properties"])
	if len(fields) != len(oldFields) || !reflect.DeepEqual(fields["schema_version"], map[string]any{"const": float64(4)}) {
		t.Fatal("v4 version or root fields")
	}
	for key, value := range oldFields {
		if key != "schema_version" && key != "connections" && key != "verification_route_record_identity" && !reflect.DeepEqual(value, fields[key]) {
			t.Fatalf("v3 root field changed: %s", key)
		}
	}
	verifier := schemaFixtureMap(t, fields["verification_route_record_identity"])
	if verifier["description"] != "Exact inventory record grant for independent verification; brokered generation requires its named profile and an approved direct verifier." {
		t.Fatal("v4 direct verifier description")
	}
	delete(verifier, "description")
	oldVerifier := schemaFixtureMap(t, oldFields["verification_route_record_identity"])
	delete(oldVerifier, "description")
	if !reflect.DeepEqual(verifier, oldVerifier) {
		t.Fatal("v4 verifier grant constraint changed")
	}
	oldArray, array := schemaFixtureMap(t, oldFields["connections"]), schemaFixtureMap(t, fields["connections"])
	for _, key := range []string{"type", "minItems", "maxItems"} {
		if !reflect.DeepEqual(array[key], oldArray[key]) {
			t.Fatalf("connection array constraint changed: %s", key)
		}
	}
	oldItems, items := schemaFixtureMap(t, oldArray["items"]), schemaFixtureMap(t, array["items"])
	if items["type"] != "object" || items["additionalProperties"] != false || !reflect.DeepEqual(items["required"], oldItems["required"]) {
		t.Fatal("v4 connection closure or generic required fields")
	}
	oldConnections, connections := schemaFixtureMap(t, oldItems["properties"]), schemaFixtureMap(t, items["properties"])
	if len(connections) != len(oldConnections)+1 || !reflect.DeepEqual(connections["request_profile"], map[string]any{"enum": []any{"openrouter_zdr_chat_v1", "opencode_go_chat_v1"}}) {
		t.Fatal("v4 finite profile fields")
	}
	for key, value := range oldConnections {
		if key != "request_profile" && !reflect.DeepEqual(value, connections[key]) {
			t.Fatalf("v3 connection constraint changed: %s", key)
		}
	}
	authority := schemaFixtureMap(t, connections["opencode_go_authority"])
	authorityFields := schemaFixtureMap(t, authority["properties"])
	assertExactSchemaFields(t, authority, authorityFields, "route_record_identity evidence_manifest_digest account_policy_identity tenant_id repository_id valid_from valid_until")
	routerFields := schemaFixtureMap(t, schemaFixtureMap(t, connections["brokered_route_authority"])["properties"])
	for key, value := range authorityFields {
		if !reflect.DeepEqual(value, routerFields[key]) {
			t.Fatalf("Go authority constraint changed: %s", key)
		}
	}
	branches, ok := items["allOf"].([]any)
	oldBranches := oldItems["allOf"].([]any)
	if !ok || len(branches) != 1 || !reflect.DeepEqual(branches[0], oldBranches[0]) {
		t.Fatal("generic credential constraint changed")
	}
	choices, ok := items["oneOf"].([]any)
	if !ok || len(choices) != 3 || !reflect.DeepEqual(choices[0], map[string]any{"not": map[string]any{"anyOf": []any{
		map[string]any{"required": []any{"request_profile"}},
		map[string]any{"required": []any{"brokered_route_authority"}},
		map[string]any{"required": []any{"opencode_go_authority"}},
	}}}) {
		t.Fatal("generic branch must forbid all named-profile fields, including null presence")
	}
	for index, profile := range []struct{ name, authority, excluded, endpoint string }{
		{"openrouter_zdr_chat_v1", "brokered_route_authority", "opencode_go_authority", "https://openrouter.ai/api/v1"},
		{"opencode_go_chat_v1", "opencode_go_authority", "brokered_route_authority", "https://opencode.ai/inference/go/openai/v1"},
	} {
		expected := map[string]any{
			"required": []any{"request_profile", profile.authority, "credential_environment"},
			"properties": map[string]any{
				"request_profile": map[string]any{"const": profile.name},
				"implementation":  map[string]any{"const": "openai_chat_completions"},
				"credential_mode": map[string]any{"const": "bearer"},
				"endpoint":        map[string]any{"const": profile.endpoint},
			},
			"not": map[string]any{"required": []any{profile.excluded}},
		}
		if !reflect.DeepEqual(choices[index+1], expected) {
			t.Fatalf("named branch not closed to exact authority, Chat, bearer and endpoint: %s", profile.name)
		}
	}
}
