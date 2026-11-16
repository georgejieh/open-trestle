package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestRuntimePolicyV4OpenCodeGoProfileAdmission(t *testing.T) {
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
	policy, err := DecodeRuntimePolicy(ctx, bytes.NewReader(marshal(policyWire)), inventory)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatalf("proposed v4 Go profile not admitted: %v", err)
	}
}
