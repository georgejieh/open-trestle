package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func setupOpenCodeGoDocuments(t *testing.T, verifierLogging bool) ([]byte, []byte) {
	t.Helper()
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
	if err := json.Unmarshal([]byte(`{"opencode_go_privacy":{"contract":"open-trestle/opencode-go-privacy-witness","schema_version":1,"route":{"zone":"brokered_remote","provider_id":"opencode-go","adapter_id":"adapter-a","connection_id":"connection-a","model_id":"glm-5.3-flash","model_version":"","effective_selector":"glm-5.3-flash"},"endpoint":"https://opencode.ai/inference/go/openai/v1","request_profile":"opencode_go_chat_v1","protocol":"openai_chat_completions","credential_mode":"bearer","model_privacy":{"training":"disabled","retention_days":0},"broker_privacy":{"retention_contract":"model_specific_documented_zero_days"},"tenant_id":"tenant-a","repository_id":"repo-a","reviewed_at":"2026-10-29T00:00:00Z","valid_from":"2026-10-29T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","byok":"excluded","tools":"excluded","plugins":"excluded","streaming":"excluded","client":{"user_agent":"open-trestle/1","session_derivation":"authorized_review_scope_sha256_v1"}}}`), &manifest); err != nil {
		t.Fatal(err)
	}
	witness := manifest["opencode_go_privacy"].(map[string]any)
	witness["account"] = account
	witness["model_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/glm-5.3-flash-privacy", "2026-10-29T00:00:00Z", digest("synthetic documented exact model zero-day no-training review")}
	witness["broker_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/broker-privacy-scope", "2026-10-29T00:00:00Z", digest("synthetic broker privacy scope review")}

	invDoc, polDoc := setupRuntimeDocuments(t, "private_remote", []string{"https://opencode.ai/inference/go/openai/v1", "https://verifier.example/v1"}, 100000, false)
	var inventoryWire, policyWire map[string]any
	if json.Unmarshal(invDoc, &inventoryWire) != nil || json.Unmarshal(polDoc, &policyWire) != nil {
		t.Fatal("fixture JSON")
	}
	routes := inventoryWire["routes"].([]any)
	generation := routes[0].(map[string]any)
	generation["zone"], generation["provider_id"], generation["model_id"], generation["model_version"] = "brokered_remote", "opencode-go", "glm-5.3-flash", ""
	generation["evidence_manifest_base64"] = base64.StdEncoding.EncodeToString(marshal(manifest))
	for _, route := range routes {
		row := route.(map[string]any)
		row["input_micro_usd_per_million_tokens"], row["output_micro_usd_per_million_tokens"] = uint64(1000), uint64(2000)
	}
	if verifierLogging {
		routes[1].(map[string]any)["content_logging"] = "enabled"
	}
	invDoc = marshal(inventoryWire)
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
	if err != nil {
		t.Fatal("Go inventory fixture", err)
	}
	records := map[string]string{}
	evidence := ""
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		adapter := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()
		records[adapter] = record.Identity()
		if adapter == "adapter-a" {
			evidence = record.EvidenceManifestDigest()
		}
	}
	policyWire["schema_version"], policyWire["inventory_identity"] = 4, inventory.Identity()
	policyWire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	policyWire["pinned_route_record_identity"], policyWire["verification_route_record_identity"] = records["adapter-a"], records["adapter-b"]
	connections := policyWire["connections"].([]any)
	connection := connections[0].(map[string]any)
	connection["implementation"], connection["request_profile"], connection["credential_environment"] = "openai_chat_completions", "opencode_go_chat_v1", "OPEN_TRESTLE_PROVIDER_OPENCODE_GO"
	connection["opencode_go_authority"] = map[string]any{"route_record_identity": records["adapter-a"], "evidence_manifest_digest": evidence, "account_policy_identity": digest(string(marshal(accountPreimage))), "tenant_id": "tenant-a", "repository_id": "repo-a", "valid_from": "2026-10-29T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}
	polDoc = marshal(policyWire)
	return invDoc, polDoc
}

func TestSetupOpenCodeGoExactPairPassesRuntimePolicyChecker(t *testing.T) {
	invDoc, polDoc := setupOpenCodeGoDocuments(t, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, err := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Posture().Inference() != InferenceApprovedRemote || plan.Posture().Egress() != EgressAllowlisted || plan.Posture().PublicationEnabled() {
		t.Fatal("wrong controlled-hybrid fixture posture")
	}
	clock := &brokeredSetupClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	checker, err := NewRuntimePolicyCheckerWithClock(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy), clock)
	if err != nil {
		t.Fatal("valid immutable Go fixture refused before check", err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed {
		t.Fatalf("Go exact approved pair blocked by setup: state=%s", result.State())
	}
}

func TestSetupOpenCodeGoVerifierLoggingUsesSharedGuard(t *testing.T) {
	invDoc, polDoc := setupOpenCodeGoDocuments(t, true)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, err := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewRuntimePolicyCheckerWithClock(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy), &brokeredSetupClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteProviderAuthorizationChecker(checker)
	if err != nil {
		t.Fatal(err)
	}
	if checker.Check(context.Background(), plan).State() != CheckBlocked || remote.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("shared verifier logging guard bypassed")
	}
}

func TestSetupOpenCodeGoLocalOnlyNeverBuildsInferenceCatalog(t *testing.T) {
	invDoc, polDoc := setupOpenCodeGoDocuments(t, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewRuntimePolicyCheckerWithClock(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy), &brokeredSetupClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if checker.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("remote Go admitted locally")
	}
	// Isolate local-only refusal even with an exact synthetic passed-policy receipt.
	plan = policyCheckedPlan(t, plan, checker)
	factory := &localInferenceFixtureFactory{}
	local, err := NewLocalInferenceChecker(checker, factory)
	if err != nil {
		t.Fatal(err)
	}
	if local.Check(context.Background(), plan).State() != CheckBlocked || factory.calls != 0 || factory.dispatches != 0 {
		t.Fatal("remote Go reached local inference factory")
	}
}
