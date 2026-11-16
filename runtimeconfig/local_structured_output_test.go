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
	doc["schema_version"] = 6
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
	if err != nil || old.Identity() == legacy.Identity() || bytes.Equal(disabled, original) {
		t.Fatal("explicit v6 false silently migrated to legacy v2")
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
			doc["schema_version"] = 6
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

func TestRuntimePolicyV6GenericBinding(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	var template map[string]any
	if err := json.Unmarshal(bindingTemplate(t), &template); err != nil {
		t.Fatal(err)
	}
	template["schema_version"] = 6
	for _, value := range template["connections"].([]any) {
		value.(map[string]any)["implementation"] = "openai_chat_completions"
	}
	omitted, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, template), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatalf("explicit v6 template refused: %v", err)
	}
	plain, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(omitted), inventory)
	if err != nil || plain.schemaVersion != 6 {
		t.Fatalf("v6 not retained: %v", err)
	}
	for _, enabled := range []bool{false, true} {
		for _, noAuth := range []bool{false, true} {
			for _, value := range template["connections"].([]any) {
				c := value.(map[string]any)
				c["local_structured_output"] = enabled
				if noAuth {
					delete(c, "credential_environment")
					c["credential_mode"] = "none"
				}
			}
			bound, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, template), "adapter-a", "adapter-b")
			if err != nil {
				t.Fatalf("v6 enabled=%v noAuth=%v: %v", enabled, noAuth, err)
			}
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bound), inventory)
			if err != nil || policy.schemaVersion != 6 || policy.ValidateAgainstInventory(inventory) != nil {
				t.Fatalf("bound v6 invalid: %v", err)
			}
			for _, c := range policy.Connections() {
				if c.LocalStructuredOutput() != enabled {
					t.Fatal("option lost")
				}
			}
			if !enabled && !noAuth && (!bytes.Equal(bound, omitted) || policy.Identity() != plain.Identity()) {
				t.Fatal("v6 false differs from omitted")
			}
			if enabled && policy.Identity() == plain.Identity() {
				t.Fatal("v6 true lost identity")
			}
		}
		if err := json.Unmarshal(bindingTemplate(t), &template); err != nil {
			t.Fatal(err)
		}
		template["schema_version"] = 6
		for _, value := range template["connections"].([]any) {
			value.(map[string]any)["implementation"] = "openai_chat_completions"
		}
	}
	legacyTemplate := bytes.Replace(bindingMarshal(t, template), []byte(`"schema_version":6`), []byte(`"schema_version":2`), 1)
	legacy, err := bindRuntimePolicy(context.Background(), inventory, legacyTemplate, "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	old, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(legacy), inventory)
	if err != nil || old.Identity() == plain.Identity() {
		t.Fatal("explicit v6 migrated legacy identity")
	}
}

func TestRuntimePolicyV6RejectsHistoricalOptionsAndMalformedFields(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	bound, err := bindRuntimePolicy(context.Background(), inventory, bindingTemplate(t), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 5; version++ {
		for _, enabled := range []bool{false, true} {
			var doc map[string]any
			if err := json.Unmarshal(bound, &doc); err != nil {
				t.Fatal(err)
			}
			doc["schema_version"] = version
			if version == 1 {
				delete(doc, "verification_route_record_identity")
			}
			doc["connections"].([]any)[0].(map[string]any)["local_structured_output"] = enabled
			if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bindingMarshal(t, doc)), inventory); err == nil {
				t.Errorf("v%d accepted option=%v", version, enabled)
			}
			if _, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, doc), "adapter-a", "adapter-b"); err == nil {
				t.Errorf("binder accepted v%d option=%v", version, enabled)
			}
		}
	}
	base := bytes.Replace(bound, []byte(`"schema_version":2`), []byte(`"schema_version":6`), 1)
	base = bytes.ReplaceAll(base, []byte("openai_responses"), []byte("openai_chat_completions"))
	for _, field := range []string{
		`"local_structured_output":null`, `"local_structured_output":"false"`, `"local_structured_output":0`,
		`"Local_Structured_Output":false`, `"local_structured_output":false,"local_structured_output":true`,
		`"request_profile":""`, `"request_profile":null`, `"Request_Profile":""`, `"brokered_route_authority":null`, `"brokered_route_authority":{}`, `"Brokered_Route_Authority":{}`,
		`"opencode_go_authority":{}`, `"opencode_go_authority":null`, `"OpenCode_Go_Authority":{}`, `"opencode_console_authority":{}`, `"opencode_console_authority":null`, `"OpenCode_Console_Authority":{}`,
	} {
		for _, option := range []string{"", `"local_structured_output":false,`, `"local_structured_output":true,`} {
			t.Run(option+field, func(t *testing.T) {
				encoded := bytes.Replace(base, []byte(`"implementation":`), []byte(option+field+`,"implementation":`), 1)
				if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory); err == nil {
					t.Fatal("decoder accepted malformed or named-profile field")
				}
				if _, err := bindRuntimePolicy(context.Background(), inventory, encoded, "adapter-a", "adapter-b"); err == nil {
					t.Fatal("binder accepted malformed or named-profile field")
				}
			})
		}
	}
}

func TestRuntimePolicyV6LocalRestrictions(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	bound, err := bindRuntimePolicy(context.Background(), inventory, bindingTemplate(t), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://127.0.0.1:11434/v1", "https://127.2.3.4/v1", "http://[::1]:11434/v1", "http://localhost:11434/v1", "https://api.example.test/v1", "http://127.0.0.1.example.test/v1"} {
		for _, implementation := range []string{"openai_chat_completions", "openai_responses"} {
			var doc map[string]any
			if err := json.Unmarshal(bound, &doc); err != nil {
				t.Fatal(err)
			}
			doc["schema_version"] = 6
			c := doc["connections"].([]any)[0].(map[string]any)
			c["local_structured_output"], c["implementation"], c["endpoint"] = true, implementation, endpoint
			_, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bindingMarshal(t, doc)), inventory)
			valid := implementation == "openai_chat_completions" && (endpoint == "http://127.0.0.1:11434/v1" || endpoint == "https://127.2.3.4/v1" || endpoint == "http://[::1]:11434/v1")
			if valid != (err == nil) {
				t.Errorf("endpoint=%s implementation=%s valid=%v err=%v", endpoint, implementation, valid, err)
			}
		}
	}
	var wire routeInventoryWire
	if err := json.Unmarshal(bindingInventoryDocument(t), &wire); err != nil {
		t.Fatal(err)
	}
	wire.Routes[0].Zone = "private_remote"
	nonlocal := bindingInventory(t, bindingMarshal(t, wire))
	var doc map[string]any
	if err := json.Unmarshal(bound, &doc); err != nil {
		t.Fatal(err)
	}
	doc["schema_version"], doc["inventory_identity"] = 6, nonlocal.Identity()
	ids := bindingRecordIDs(nonlocal)
	doc["pinned_route_record_identity"], doc["verification_route_record_identity"] = ids["adapter-a"], ids["adapter-b"]
	for _, value := range doc["connections"].([]any) {
		c := value.(map[string]any)
		c["implementation"], c["local_structured_output"] = "openai_chat_completions", true
	}
	if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bindingMarshal(t, doc)), nonlocal); err == nil {
		t.Fatal("option accepted nonlocal inventory namespace")
	}
}
