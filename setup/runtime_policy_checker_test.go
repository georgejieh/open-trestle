package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func setupRuntimeDocuments(t *testing.T, zone string, endpoints []string, maxCost uint64, contentLogging bool) ([]byte, []byte) {
	t.Helper()
	routes := make([]map[string]any, len(endpoints))
	for i := range endpoints {
		suffix := string(rune('a' + i))
		routes[i] = map[string]any{"zone": zone, "provider_id": "provider-" + suffix, "adapter_id": "adapter-" + suffix, "connection_id": "connection-" + suffix, "model_id": "model-" + suffix, "model_version": "v1", "max_context_tokens": uint64(64000), "max_output_tokens": uint64(8192), "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": uint64(0), "output_micro_usd_per_million_tokens": uint64(0), "quality": "tier_3", "registry_revision": uint64(1), "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"approved":true}`)), "operational_revision": uint64(1), "health": "healthy", "quota": "available", "performance_revision": uint64(1), "latency_known": false, "p95_latency_milliseconds": uint32(0), "latency_sample_count": uint32(0)}
	}
	inventoryDocument, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryDocument))
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]map[string]any, len(endpoints))
	for i, endpoint := range endpoints {
		suffix := string(rune('a' + i))
		connections[i] = map[string]any{"implementation": "openai_responses", "adapter_id": "adapter-" + suffix, "endpoint": endpoint, "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_" + strings.ToUpper(suffix)}
	}
	policyDocument, _ := json.Marshal(map[string]any{"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("a", 64), "min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{zone}, "content_logging_allowed": contentLogging, "estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": maxCost, "pinned_route_record_identity": "", "preferred_route_record_identities": []string{}, "verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true, "connections": connections})
	return inventoryDocument, policyDocument
}
func parseSetupRuntimeDocuments(t *testing.T, inventoryDocument, policyDocument []byte) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) {
	t.Helper()
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryDocument))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyDocument), inventory)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, policy
}
func setupRuntimeApproval(t *testing.T, plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) RuntimePolicyApproval {
	t.Helper()
	approval, err := NewRuntimePolicyApproval(plan, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity(), plan.RecoveryOwner())
	if err != nil {
		t.Fatal(err)
	}
	return approval
}
func TestRuntimePolicyCheckerMatchesLocalPosture(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	if err != nil {
		t.Fatal(err)
	}
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckPassed || result.validate(CheckPolicyValidated) != nil {
		t.Fatalf("result=%#v", result)
	}
}
func TestRuntimePolicyCheckerRejectsPostureMismatch(t *testing.T) {
	tests := []struct {
		name, zone string
		endpoints  []string
		cost       uint64
		logging    bool
		profile    Profile
	}{{"remote local profile", "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 0, false, ProfileLocalSingleNode}, {"overspend", "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100001, false, ProfileControlledHybrid}, {"content logging", "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, true, ProfileControlledHybrid}, {"insufficient independence", "local", []string{"http://127.0.0.1:11434/v1"}, 0, false, ProfileLocalSingleNode}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, p := setupRuntimeDocuments(t, tt.zone, tt.endpoints, tt.cost, tt.logging)
			inventory, policy := parseSetupRuntimeDocuments(t, i, p)
			plan, _ := NewPlan(tt.profile, "tenant-a", "repo-a", "owner", setupTime(1))
			checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
				t.Fatalf("state=%s", result.State())
			}
		})
	}
}
func TestRuntimePolicyFileCheckerReportsUnavailableAndRejectsUnsafeFile(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing-inventory.json")
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	fixtureInventory, fixturePolicy := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	parsedInventory, parsedPolicy := parseSetupRuntimeDocuments(t, fixtureInventory, fixturePolicy)
	approval := setupRuntimeApproval(t, plan, parsedInventory, parsedPolicy)
	checker, err := NewRuntimePolicyFileChecker(missing, filepath.Join(root, "missing-policy.json"), approval)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckUnavailable {
		t.Fatalf("missing=%s", result.State())
	}
	inv, pol := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	invPath, polPath := filepath.Join(root, "inventory.json"), filepath.Join(root, "policy.json")
	if os.WriteFile(invPath, inv, 0o600) != nil || os.WriteFile(polPath, pol, 0o600) != nil {
		t.Fatal("write")
	}
	_ = os.Chmod(invPath, 0o666)
	checker, _ = NewRuntimePolicyFileChecker(invPath, polPath, approval)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("unsafe=%s", result.State())
	}
	_ = os.Chmod(invPath, 0o600)
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed {
		t.Fatalf("safe=%s", result.State())
	}
}
func TestRuntimePolicyCheckerPersistsOnlyCanonicalEvidence(t *testing.T) {
	root := t.TempDir()
	state, _ := OpenStateFile(filepath.Join(root, "plan.json"))
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	if err := state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	inv, pol := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, inv, pol)
	checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{time.UnixMilli(2).UTC()})
	next, receipt, err := runner.Run(context.Background(), CheckPolicyValidated)
	if err != nil || receipt.State() != CheckPassed || next.Revision() != 2 {
		t.Fatalf("run=%s %d %v", receipt.State(), next.Revision(), err)
	}
	encoded, _ := EncodeCheckReceipt(receipt)
	if bytes.Contains(encoded, []byte("127.0.0.1")) || bytes.Contains(encoded, []byte("OPEN_TRESTLE_PROVIDER")) {
		t.Fatal("configuration leaked")
	}
}

func TestRuntimePolicyApprovalBindsRootScopeActorAndExactConfiguration(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	if approval, err := NewRuntimePolicyApproval(plan, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity(), "other"); err == nil || approval.Identity() != "" {
		t.Fatal("wrong actor accepted")
	}
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	if !approval.validate(plan, inventory, policy) || approval.Identity() == inventory.Identity() || fmt.Sprint(approval) != "setup runtime policy approval" || strings.Contains(fmt.Sprintf("%#v", approval), "owner") {
		t.Fatal("approval invalid or leaked")
	}
	otherPlan, _ := NewPlan(ProfileLocalSingleNode, "tenant-b", "repo-b", "owner", setupTime(1))
	if approval.validate(otherPlan, inventory, policy) {
		t.Fatal("cross-scope approval accepted")
	}
}
func TestRuntimePolicyCheckerRejectsWeakerPublicationGate(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	for _, mutation := range []func([]byte) []byte{func(value []byte) []byte {
		return bytes.Replace(value, []byte(`"publication_block_on_inconclusive":true`), []byte(`"publication_block_on_inconclusive":false`), 1)
	}, func(value []byte) []byte {
		return bytes.Replace(value, []byte(`"publication_minimum_independence":"distinct_provider"`), []byte(`"publication_minimum_independence":"distinct_route"`), 1)
	}} {
		changed := mutation(polDoc)
		inventory, policy := parseSetupRuntimeDocuments(t, invDoc, changed)
		plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
		checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
		if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
			t.Fatalf("state=%s", result.State())
		}
	}
}

func TestRuntimePolicyFileCheckerRejectsReplaceableAncestryAndSymlink(t *testing.T) {
	root := t.TempDir()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	world := filepath.Join(root, "world")
	_ = os.Mkdir(world, 0o777)
	_ = os.Chmod(world, 0o777)
	parent := filepath.Join(world, "parent")
	_ = os.Mkdir(parent, 0o700)
	inventoryPath, policyPath := filepath.Join(parent, "routes.json"), filepath.Join(parent, "policy.json")
	_ = os.WriteFile(inventoryPath, invDoc, 0o600)
	_ = os.WriteFile(policyPath, polDoc, 0o600)
	checker, _ := NewRuntimePolicyFileChecker(inventoryPath, policyPath, approval)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("replaceable=%s", result.State())
	}
	_ = os.Chmod(world, 0o700)
	link := filepath.Join(parent, "policy-link.json")
	_ = os.Symlink(policyPath, link)
	checker, _ = NewRuntimePolicyFileChecker(inventoryPath, link, approval)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("symlink=%s", result.State())
	}
}
func TestRuntimePolicyFileCheckerRecordsMalformedConfigurationAsBlocked(t *testing.T) {
	root := t.TempDir()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	inventoryPath, policyPath := filepath.Join(root, "routes.json"), filepath.Join(root, "policy.json")
	_ = os.WriteFile(inventoryPath, invDoc, 0o600)
	_ = os.WriteFile(policyPath, []byte(`{}`), 0o600)
	checker, _ := NewRuntimePolicyFileChecker(inventoryPath, policyPath, approval)
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckBlocked || result.validate(CheckPolicyValidated) != nil {
		t.Fatalf("malformed=%#v", result)
	}
}

func TestRuntimePolicyCheckerRejectsPinnedGenerationRoute(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, _ := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
	var document map[string]any
	if json.Unmarshal(polDoc, &document) != nil {
		t.Fatal("decode")
	}
	document["pinned_route_record_identity"] = inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	changed, _ := json.Marshal(document)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, changed)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("state=%s", result.State())
	}
}

func TestRuntimePolicyCheckerRejectsAmbiguousLocalityAndAdapterNamespace(t *testing.T) {
	t.Run("localhost remote", func(t *testing.T) {
		invDoc, polDoc := setupRuntimeDocuments(t, "private_remote", []string{"https://localhost/v1", "https://two.example/v1"}, 100000, false)
		inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
		if err != nil {
			t.Fatal(err)
		}
		policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(polDoc), inventory)
		if err == nil || policy.Identity() != "" {
			t.Fatal("localhost remote endpoint decoded")
		}
	})
	t.Run("shared adapter divergent authority", func(t *testing.T) {
		invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
		var inventoryWire map[string]any
		_ = json.Unmarshal(invDoc, &inventoryWire)
		routes := inventoryWire["routes"].([]any)
		routes[1].(map[string]any)["adapter_id"] = "adapter-a"
		invDoc, _ = json.Marshal(inventoryWire)
		inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
		if err != nil {
			t.Fatal(err)
		}
		var policyWire map[string]any
		_ = json.Unmarshal(polDoc, &policyWire)
		policyWire["inventory_identity"] = inventory.Identity()
		policyWire["connections"] = []any{policyWire["connections"].([]any)[0]}
		polDoc, _ = json.Marshal(policyWire)
		policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(polDoc), inventory)
		if err == nil || policy.Identity() != "" {
			t.Fatal("ambiguous adapter namespace decoded")
		}
	})
}
