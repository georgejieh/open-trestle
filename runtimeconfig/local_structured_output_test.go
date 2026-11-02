package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestLocalStructuredOutputPolicyBindingAndLegacyIdentity(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	template := bytes.ReplaceAll(bindingTemplate(t), []byte("openai_responses"), []byte("openai_chat_completions"))
	original, err := bindRuntimePolicy(context.Background(), inventory, template, "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(original), inventory)
	if err != nil {
		t.Fatal(err)
	}
	type legacyConnection struct {
		Implementation           string                             `json:"implementation"`
		AdapterID                string                             `json:"adapter_id"`
		Endpoint                 string                             `json:"endpoint"`
		CredentialEnvironment    string                             `json:"credential_environment,omitempty"`
		CredentialMode           string                             `json:"credential_mode,omitempty"`
		RequestProfile           string                             `json:"request_profile,omitempty"`
		BrokeredAuthority        *brokeredRouteAuthorityWire        `json:"brokered_route_authority,omitempty"`
		OpenCodeGoAuthority      *openCodeGoRouteAuthorityWire      `json:"opencode_go_authority,omitempty"`
		OpenCodeConsoleAuthority *openCodeConsoleRouteAuthorityWire `json:"opencode_console_authority,omitempty"`
	}
	connectionsBeforeOption := make([]legacyConnection, len(legacy.connections))
	for i, c := range legacy.connections {
		connectionsBeforeOption[i] = legacyConnection{Implementation: c.implementation, AdapterID: c.adapterID, Endpoint: c.endpoint, CredentialEnvironment: c.credentialEnvironment}
	}
	preimage := bindingMarshal(t, struct {
		Contract                                                                                 string `json:"contract"`
		Version                                                                                  int    `json:"version"`
		Inventory, Policy, Requirements, Constraints, Budget, Ranking, Independence, Publication string
		Connections                                                                              []legacyConnection `json:"connections"`
		VerificationRouteRecordIdentity                                                          string             `json:"verification_route_record_identity"`
	}{"open-trestle/runtime-policy", 2, legacy.inventoryIdentity, legacy.reviewPolicyIdentity, requirementsIdentity(legacy.requirements), constraintsIdentity(legacy.constraints), budgetIdentity(legacy.budget), legacy.ranking.Identity(), legacy.independence.Identity(), legacy.publication.Identity(), connectionsBeforeOption, legacy.verificationRouteRecordIdentity})
	digest := sha256.Sum256(preimage)
	if legacy.Identity() != hex.EncodeToString(digest[:]) {
		t.Fatal("omitted option changed legacy policy preimage")
	}
	var doc map[string]any
	if json.Unmarshal(template, &doc) != nil {
		t.Fatal("template")
	}
	doc["schema_version"] = 2
	connections := doc["connections"].([]any)
	for _, c := range connections {
		c.(map[string]any)["local_structured_output"] = true
	}
	enabledTemplate := bindingMarshal(t, doc)
	enabled, err := bindRuntimePolicy(context.Background(), inventory, enabledTemplate, "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(enabled), inventory)
	if err != nil || current.Identity() == legacy.Identity() || !current.Connections()[0].LocalStructuredOutput() || current.ValidateAgainstInventory(inventory) != nil {
		t.Fatalf("option lost during binding: %v", err)
	}
	for _, c := range connections {
		c.(map[string]any)["local_structured_output"] = false
	}
	disabled, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, doc), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	old, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(disabled), inventory)
	if err != nil || old.Identity() != legacy.Identity() || !bytes.Equal(disabled, original) {
		t.Fatal("explicit false changed legacy identity or bound bytes")
	}
}

func TestLocalStructuredOutputPolicyRejectsInvalidDeclarations(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	original, err := bindRuntimePolicy(context.Background(), inventory, bindingTemplate(t), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"responses", func(d, c map[string]any) { c["local_structured_output"] = true }},
		{"remote endpoint", func(d, c map[string]any) {
			c["implementation"] = "openai_chat_completions"
			c["endpoint"] = "https://api.example.test/v1"
			c["local_structured_output"] = true
		}},
		{"localhost", func(d, c map[string]any) {
			c["implementation"] = "openai_chat_completions"
			c["endpoint"] = "http://localhost:1/v1"
			c["local_structured_output"] = true
		}},
		{"null", func(d, c map[string]any) { c["local_structured_output"] = nil }},
		{"string", func(d, c map[string]any) { c["local_structured_output"] = "false" }},
		{"number", func(d, c map[string]any) { c["local_structured_output"] = 0 }},
		{"wrong case", func(d, c map[string]any) { c["Local_Structured_Output"] = false }},
		{"v1 false", func(d, c map[string]any) {
			d["schema_version"] = 1
			delete(d, "verification_route_record_identity")
			c["local_structured_output"] = false
		}},
		{"v3 false", func(d, c map[string]any) { d["schema_version"] = 3; c["local_structured_output"] = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var doc map[string]any
			if json.Unmarshal(original, &doc) != nil {
				t.Fatal("policy")
			}
			c := doc["connections"].([]any)[0].(map[string]any)
			test.mutate(doc, c)
			if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bindingMarshal(t, doc)), inventory); err == nil {
				t.Fatal("accepted invalid declaration")
			}
		})
	}
	duplicate := bytes.Replace(original, []byte(`"implementation":`), []byte(`"local_structured_output":false,"local_structured_output":false,"implementation":`), 1)
	if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(duplicate), inventory); err == nil {
		t.Fatal("accepted duplicate option")
	}
}
