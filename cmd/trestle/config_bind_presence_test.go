package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestConfigBindPreservesCredentialPresenceValidation(t *testing.T) {
	for _, test := range []struct {
		name        string
		version     int
		mode        string
		environment bool
		wantSuccess bool
	}{
		{name: "valid_v2_none", version: 2, mode: "none", wantSuccess: true},
		{name: "valid_v2_explicit_bearer", version: 2, mode: "bearer", environment: true, wantSuccess: true},
		{name: "v2_none_empty_environment", version: 2, mode: "none", environment: true},
		{name: "v2_empty_mode", version: 2, mode: "", environment: true},
		{name: "v2_wrong_case_mode", version: 2, mode: "Bearer", environment: true},
		{name: "v1_explicit_bearer", version: 1, mode: "bearer", environment: true},
		{name: "v1_explicit_none", version: 1, mode: "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventoryBytes := bytes.Replace(configIdentityInventoryDocument(t, "local-model-generation", "local-model-verification"),
				[]byte(`"provider_id":"openai","adapter_id":"openai-responses-2"`),
				[]byte(`"provider_id":"verifier","adapter_id":"openai-responses-2"`), 1)
			var template map[string]any
			if err := json.Unmarshal(configBindTemplate("http://127.0.0.1:11434/v1"), &template); err != nil {
				t.Fatal(err)
			}
			template["schema_version"] = test.version
			for _, raw := range template["connections"].([]any) {
				connection := raw.(map[string]any)
				connection["credential_mode"] = test.mode
				if !test.environment {
					delete(connection, "credential_environment")
				} else if test.mode == "none" {
					connection["credential_environment"] = ""
				}
			}
			templateBytes, err := json.Marshal(template)
			if err != nil {
				t.Fatal(err)
			}
			inventoryPath := writeConfigIdentityProtectedFile(t, "routes.json", inventoryBytes, 0600)
			templatePath := writeConfigIdentityProtectedFile(t, "template.json", templateBytes, 0600)
			var stdout, stderr bytes.Buffer
			code := runConfig(configBindArgs(inventoryPath, templatePath), &stdout, &stderr)
			if test.wantSuccess {
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("valid binding code=%d stderr=%q", code, stderr.String())
				}
				inventory := decodeConfigIdentityInventory(t, inventoryBytes)
				policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(stdout.Bytes()), inventory)
				if err != nil || policy.ValidateAgainstInventory(inventory) != nil || policy.VerificationRouteRecordIdentity() == "" {
					t.Fatalf("bound output is not a valid v2 policy: %v", err)
				}
				for _, connection := range policy.Connections() {
					if connection.CredentialMode() != test.mode {
						t.Fatal("binding changed credential mode")
					}
				}
			} else if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid credential intent accepted: code=%d stdout bytes=%d stderr=%q", code, stdout.Len(), stderr.String())
			}
			for path, expected := range map[string][]byte{inventoryPath: inventoryBytes, templatePath: templateBytes} {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("binding changed a protected input")
				}
			}
		})
	}
}
