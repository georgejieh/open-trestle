package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func openCodeGoStaticFixture(t *testing.T, mutateManifest func([]byte) []byte) (RouteInventory, map[string]any) {
	t.Helper()
	ctx := context.Background()
	digest := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	marshal := func(value any) []byte {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	type source struct {
		URL           string `json:"url"`
		RetrievedAt   string `json:"retrieved_at"`
		ContentSHA256 string `json:"content_sha256"`
	}
	account := struct {
		AuthorityLabel              string `json:"authority_label"`
		CredentialReferenceIdentity string `json:"credential_reference_identity"`
		Subscription                string `json:"subscription"`
		WorkspaceMembership         string `json:"workspace_membership"`
		PrivacyTraining             string `json:"privacy_training"`
		ExtraUsage                  string `json:"extra_usage"`
		ReviewEvidence              source `json:"review_evidence"`
	}{"synthetic Go single-member account, not live approval", digest("open-trestle/provider-credential-environment/OPEN_TRESTLE_PROVIDER_OPENCODE_GO"), "go", "single_member", "disabled", "disabled", source{"https://account-review.fixture.invalid/go/privacy-and-extra-usage", "2026-10-29T00:00:00Z", digest("synthetic account privacy and Extra Usage off review")}}
	accountPreimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{"open-trestle/opencode-go-account-policy", 1, account}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(`{"opencode_go_privacy":{"contract":"open-trestle/opencode-go-privacy-witness","schema_version":1,"route":{"zone":"brokered_remote","provider_id":"opencode-go","adapter_id":"adapter-a","connection_id":"primary/opencode-go","model_id":"glm-5.3-flash","model_version":"","effective_selector":"glm-5.3-flash"},"endpoint":"https://opencode.ai/inference/go/openai/v1","request_profile":"opencode_go_chat_v1","protocol":"openai_chat_completions","credential_mode":"bearer","model_privacy":{"training":"disabled","retention_days":0},"broker_privacy":{"retention_contract":"model_specific_documented_zero_days"},"tenant_id":"tenant-a","repository_id":"repository-a","reviewed_at":"2026-10-29T00:00:00Z","valid_from":"2026-10-29T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","byok":"excluded","tools":"excluded","plugins":"excluded","streaming":"excluded","client":{"user_agent":"open-trestle/1","session_derivation":"authorized_review_scope_sha256_v1"}}}`), &manifest); err != nil {
		t.Fatal(err)
	}
	witness := manifest["opencode_go_privacy"].(map[string]any)
	witness["account"] = account
	witness["model_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/glm-5.3-flash-privacy", "2026-10-29T00:00:00Z", digest("synthetic documented exact model zero-day no-training review")}
	witness["broker_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/broker-privacy-scope", "2026-10-29T00:00:00Z", digest("synthetic broker privacy scope review")}
	generation := routeDefinition(t, "glm-5.3-flash")
	var err error
	generation.Route, err = provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "opencode-go", "adapter-a", "primary/opencode-go", "glm-5.3-flash", "")
	if err != nil {
		t.Fatal(err)
	}
	generation.EvidenceManifest = marshal(manifest)
	if mutateManifest != nil {
		generation.EvidenceManifest = mutateManifest(generation.EvidenceManifest)
	}
	verifier := routeDefinition(t, "verifier")
	verifier.Route, err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "direct", "verifier", "primary/direct", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewRouteInventory(ctx, []RouteDefinition{generation, verifier})
	if err != nil || inventory.Validate() != nil {
		t.Fatalf("fixture inventory invalid: %v", err)
	}
	var recordID, evidenceID, verifierID string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			recordID, evidenceID = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifierID = record.Identity()
		}
	}
	var policyWire map[string]any
	if err := json.Unmarshal(runtimePolicyDocument(t, inventory), &policyWire); err != nil {
		t.Fatal(err)
	}
	policyWire["schema_version"], policyWire["allowed_zones"] = 4, []string{"brokered_remote", "private_remote"}
	policyWire["pinned_route_record_identity"], policyWire["preferred_route_record_identities"], policyWire["verification_route_record_identity"] = recordID, []string{}, verifierID
	policyWire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://opencode.ai/inference/go/openai/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENCODE_GO", "request_profile": "opencode_go_chat_v1", "opencode_go_authority": map[string]any{"route_record_identity": recordID, "evidence_manifest_digest": evidenceID, "account_policy_identity": digest(string(marshal(accountPreimage))), "tenant_id": "tenant-a", "repository_id": "repository-a", "valid_from": "2026-10-29T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
	}
	return inventory, policyWire
}

func decodeOpenCodeGoStatic(t *testing.T, inventory RouteInventory, wire map[string]any) (RuntimePolicy, error) {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
}
func TestOpenCodeGoStaticWitnessAdmissionAndCurrentWindow(t *testing.T) {
	inventory, wire := openCodeGoStaticFixture(t, nil)
	policy, err := decodeOpenCodeGoStatic(t, inventory, wire)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatal("valid synthetic Go declaration refused", err)
	}
	var authority OpenCodeGoRouteAuthority
	for _, connection := range policy.Connections() {
		if connection.RequestProfile() == OpenCodeGoChatProfile {
			authority = connection.OpenCodeGoAuthority()
		}
	}
	if authority.RouteRecordIdentity() == "" || authority.AccountPolicyIdentity() == "" || authority.TenantID() != "tenant-a" || authority.RepositoryID() != "repository-a" {
		t.Fatal("Go authority not retained")
	}
	for _, test := range []struct {
		at   time.Time
		want bool
	}{{authority.ValidFrom().Add(-time.Nanosecond), false}, {authority.ValidFrom(), true}, {authority.ValidUntil().Add(-time.Nanosecond), true}, {authority.ValidUntil(), false}} {
		if inventory.OpenCodeGoPrivacyCurrent(authority.RouteRecordIdentity(), test.at) != test.want || authority.Current(test.at) != test.want {
			t.Fatal("wrong exact declaration window")
		}
	}
	if inventory.OpenCodeGoPrivacyCurrent(strings.Repeat("e", 64), authority.ValidFrom()) || inventory.OpenRouterPrivacyCurrent(authority.RouteRecordIdentity(), authority.ValidFrom()) {
		t.Fatal("projection crossed record/provider")
	}
}
func TestOpenCodeGoStaticRefusesMalformedWitness(t *testing.T) {
	for name, mutation := range map[string]func(string) string{
		"missing":      func(s string) string { return `{"opaque":"legacy evidence"}` },
		"null section": func(s string) string { return `{"opencode_go_privacy":null}` },
		"duplicate": func(s string) string {
			return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
		},
		"case":                  func(s string) string { return strings.Replace(s, `"model_privacy"`, `"Model_privacy"`, 1) },
		"null retention":        func(s string) string { return strings.Replace(s, `"retention_days":0`, `"retention_days":null`, 1) },
		"missing retention":     func(s string) string { return strings.Replace(s, `"retention_days":0,`, ``, 1) },
		"positive retention":    func(s string) string { return strings.Replace(s, `"retention_days":0`, `"retention_days":1`, 1) },
		"missing model version": func(s string) string { return strings.Replace(s, `"model_version":"",`, ``, 1) },
		"null model version":    func(s string) string { return strings.Replace(s, `"model_version":""`, `"model_version":null`, 1) },
		"wrong model": func(s string) string {
			return strings.Replace(s, `"model_id":"glm-5.3-flash"`, `"model_id":"other-model"`, 1)
		},
		"wrong selector": func(s string) string {
			return strings.Replace(s, `"effective_selector":"glm-5.3-flash"`, `"effective_selector":"other-model"`, 1)
		},
		"extra usage": func(s string) string {
			return strings.Replace(s, `"extra_usage":"disabled"`, `"extra_usage":"enabled"`, 1)
		},
		"training": func(s string) string {
			return strings.Replace(s, `"privacy_training":"disabled"`, `"privacy_training":"enabled"`, 1)
		},
		"membership": func(s string) string {
			return strings.Replace(s, `"workspace_membership":"single_member"`, `"workspace_membership":"team"`, 1)
		},
		"review after from": func(s string) string {
			return strings.Replace(s, `"reviewed_at":"2026-10-29T00:00:00Z"`, `"reviewed_at":"2026-10-30T00:00:00Z"`, 1)
		},
		"unknown client": func(s string) string {
			return strings.Replace(s, `"user_agent":"open-trestle/1"`, `"user_agent":"open-trestle/1","extra":true`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			inventory, wire := openCodeGoStaticFixture(t, func(encoded []byte) []byte {
				changed := mutation(string(encoded))
				if changed == string(encoded) {
					t.Fatal("mutation did not reach fixture")
				}
				return []byte(changed)
			})
			policy, err := decodeOpenCodeGoStatic(t, inventory, wire)
			if err == nil || policy.Identity() != "" {
				t.Fatal("invalid witness admitted")
			}
		})
	}
}
func TestOpenCodeGoStaticRefusesPolicyOnlyChangesAndHistoricalPresence(t *testing.T) {
	for _, field := range []string{"account_policy_identity", "tenant_id", "repository_id", "valid_from", "valid_until", "credential_environment", "both authorities", "extra field", "null authority", "v1", "v2", "v3"} {
		t.Run(field, func(t *testing.T) {
			inventory, wire := openCodeGoStaticFixture(t, nil)
			connection := wire["connections"].([]any)[0].(map[string]any)
			authority := connection["opencode_go_authority"].(map[string]any)
			switch field {
			case "credential_environment":
				connection[field] = "OPEN_TRESTLE_PROVIDER_DIFFERENT"
			case "both authorities":
				connection["brokered_route_authority"] = map[string]any{}
			case "extra field":
				authority["provider_slug"] = "not-go-authority"
			case "null authority":
				connection["opencode_go_authority"] = nil
			case "valid_from":
				authority[field] = "2026-10-30T00:00:00Z"
			case "valid_until":
				authority[field] = "2026-11-02T00:00:00Z"
			case "account_policy_identity":
				authority[field] = strings.Repeat("e", 64)
			case "v1":
				wire["schema_version"] = 1
				delete(wire, "verification_route_record_identity")
			case "v2":
				wire["schema_version"] = 2
			case "v3":
				wire["schema_version"] = 3
			default:
				authority[field] = "other-value"
			}
			policy, err := decodeOpenCodeGoStatic(t, inventory, wire)
			if err == nil || policy.Identity() != "" {
				t.Fatal("unbound policy mutation admitted")
			}
		})
	}
}
func TestOpenCodeGoV4RetainsOpenRouterAndGenericAdmission(t *testing.T) {
	witness := privacyFixtureWitness(t)
	inventory := privacyFixtureInventory(t, privacyFixtureManifest(t, witness), false, true)
	wire := privacyFixturePolicy(t, inventory, privacyFixtureAccountIdentity(t, witness.Account), true, 3)
	old, err := decodeOpenCodeGoStatic(t, inventory, wire)
	if err != nil {
		t.Fatal(err)
	}
	wire["schema_version"] = 4
	next, err := decodeOpenCodeGoStatic(t, inventory, wire)
	if err != nil || next.ValidateAgainstInventory(inventory) != nil || old.Identity() == next.Identity() {
		t.Fatal("v4 lost OpenRouter or version identity", err)
	}
	genericInventory := privacyFixtureInventory(t, []byte("opaque legacy evidence"), false, false)
	generic := privacyFixturePolicy(t, genericInventory, "", false, 4)
	if policy, err := decodeOpenCodeGoStatic(t, genericInventory, generic); err != nil || policy.ValidateAgainstInventory(genericInventory) != nil {
		t.Fatal("v4 generic refused", err)
	}
	for _, version := range []int{1, 2, 3} {
		generic["schema_version"] = version
		if version == 1 {
			delete(generic, "verification_route_record_identity")
		} else {
			generic = privacyFixturePolicy(t, genericInventory, "", false, version)
		}
		connection := generic["connections"].([]any)[0].(map[string]any)
		connection["opencode_go_authority"] = nil
		if policy, err := decodeOpenCodeGoStatic(t, genericInventory, generic); err == nil || policy.Identity() != "" {
			t.Fatal("historical version ignored new null authority")
		}
	}
}
