package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func noAuthPolicyFixture(t *testing.T) (RouteInventory, map[string]any) {
	t.Helper()
	definition := routeDefinition(t, "model-a")
	prior := definition.Route
	var err error
	definition.Route, err = provider.NewRouteReference(provider.ProviderZoneLocal, prior.ProviderID(), prior.AdapterID(), prior.ConnectionID(), prior.ModelID(), prior.ModelVersion())
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(runtimePolicyDocument(t, inventory), &doc) != nil {
		t.Fatal("invalid fixture")
	}
	doc["schema_version"] = 2
	doc["verification_route_record_identity"] = inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	doc["allowed_zones"] = []string{"local"}
	c := doc["connections"].([]any)[0].(map[string]any)
	c["endpoint"] = "http://127.0.0.1:11434/v1"
	return inventory, doc
}

func TestNoAuthRuntimePolicyV2IdentityAndV1RemainExplicit(t *testing.T) {
	inventory, doc := noAuthPolicyFixture(t)
	decode := func() (RuntimePolicy, error) {
		encoded, _ := json.Marshal(doc)
		return DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	}
	implicit, err := decode()
	if err != nil {
		t.Fatal(err)
	}
	c := doc["connections"].([]any)[0].(map[string]any)
	c["credential_mode"] = "bearer"
	explicit, err := decode()
	if err != nil || explicit.Identity() != implicit.Identity() {
		t.Fatal("explicit bearer changed historical v2 identity")
	}
	c["credential_mode"] = "none"
	delete(c, "credential_environment")
	none, err := decode()
	if err != nil || none.ValidateAgainstInventory(inventory) != nil || none.Identity() == implicit.Identity() {
		t.Fatalf("NO_AUTH v2 policy: %v", err)
	}
	connection := none.Connections()[0]
	if connection.CredentialMode() != "none" || connection.CredentialEnvironment() != "" || connection.CredentialIdentity() != "" {
		t.Fatal("NO_AUTH retained secret authority")
	}
	doc["schema_version"] = 1
	delete(doc, "verification_route_record_identity")
	for _, mode := range []any{"none", "bearer", nil, ""} {
		c["credential_mode"] = mode
		if _, err := decode(); err == nil {
			t.Fatalf("v1 accepted credential_mode %v", mode)
		}
	}
	delete(c, "credential_mode")
	c["credential_environment"] = "OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"
	legacy, err := decode()
	if err != nil || legacy.Validate() != nil {
		t.Fatal("historical v1 no-mode connection no longer decodes")
	}
}

func TestNoAuthRuntimePolicyRejectsPresenceConflictsAndNonLoopback(t *testing.T) {
	for name, change := range map[string]func(map[string]any, map[string]any){
		"remote endpoint":            func(_, c map[string]any) { c["endpoint"] = "https://api.example.test/v1" },
		"localhost":                  func(_, c map[string]any) { c["endpoint"] = "http://localhost:11434/v1" },
		"credential environment":     func(_, c map[string]any) { c["credential_environment"] = "OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY" },
		"empty environment presence": func(_, c map[string]any) { c["credential_environment"] = "" },
		"null environment presence":  func(_, c map[string]any) { c["credential_environment"] = nil },
		"unknown mode":               func(_, c map[string]any) { c["credential_mode"] = "no_auth" },
		"empty mode":                 func(_, c map[string]any) { c["credential_mode"] = "" },
		"null mode":                  func(_, c map[string]any) { c["credential_mode"] = nil },
		"alternate case":             func(_, c map[string]any) { delete(c, "credential_mode"); c["Credential_Mode"] = "none" },
	} {
		t.Run(name, func(t *testing.T) {
			inventory, doc := noAuthPolicyFixture(t)
			c := doc["connections"].([]any)[0].(map[string]any)
			c["credential_mode"] = "none"
			delete(c, "credential_environment")
			change(doc, c)
			encoded, _ := json.Marshal(doc)
			if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory); err == nil {
				t.Fatal("ambiguous NO_AUTH policy admitted")
			}
		})
	}
	// Matching remote inventory and HTTPS endpoint are still not NO_AUTH authority.
	definition := routeDefinition(t, "model-a")
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(runtimePolicyDocument(t, inventory), &doc)
	doc["schema_version"] = 2
	doc["verification_route_record_identity"] = inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	c := doc["connections"].([]any)[0].(map[string]any)
	c["credential_mode"] = "none"
	delete(c, "credential_environment")
	encoded, _ := json.Marshal(doc)
	if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory); err == nil {
		t.Fatal("NO_AUTH admitted a remote namespace")
	}
}
