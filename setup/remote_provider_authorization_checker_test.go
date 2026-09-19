package setup

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemoteProviderAuthorizationRequiresExactApprovedRemotePolicy(t *testing.T) {
	inventoryDocument, policyDocument := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	checker, err := NewRemoteProviderAuthorizationChecker(policyChecker)
	if err != nil {
		t.Fatal(err)
	}
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckPassed || result.validate(CheckRemoteProviderAuthorized) != nil {
		t.Fatalf("result=%#v", result)
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(1))
	if result = checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("scope=%s", result.State())
	}
}
func TestRemoteProviderAuthorizationRejectsLocalOrUnsafeRemotePosture(t *testing.T) {
	for _, test := range []struct {
		profile   Profile
		zone      string
		endpoints []string
		cost      uint64
		logging   bool
	}{{ProfileLocalSingleNode, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false}, {ProfileControlledHybrid, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100001, false}, {ProfileControlledHybrid, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, true}} {
		inventoryDocument, policyDocument := setupRuntimeDocuments(t, test.zone, test.endpoints, test.cost, test.logging)
		inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
		plan, _ := NewPlan(test.profile, "tenant-a", "repo-a", "owner", setupTime(1))
		policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
		checker, _ := NewRemoteProviderAuthorizationChecker(policyChecker)
		if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
			t.Fatalf("profile=%s state=%s", test.profile, result.State())
		}
	}
}

func TestRemoteProviderAuthorizationFencesScopeBeforeProtectedFileRead(t *testing.T) {
	inventoryDocument, policyDocument := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	missing := t.TempDir()
	policyChecker, _ := NewRuntimePolicyFileChecker(filepath.Join(missing, "routes.json"), filepath.Join(missing, "policy.json"), approval)
	checker, _ := NewRemoteProviderAuthorizationChecker(policyChecker)
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(1))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("scope=%s", result.State())
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckUnavailable {
		t.Fatalf("missing=%s", result.State())
	}
	changedPolicy, _ := NewRuntimePolicyFileChecker(filepath.Join(missing, "routes.json"), filepath.Join(missing, "policy.json"), approval)
	changedChecker, _ := NewRemoteProviderAuthorizationChecker(changedPolicy)
	changedPolicy.inventoryPath = filepath.Join(missing, "other-routes.json")
	if result := changedChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("changed=%s", result.State())
	}
}

func TestRemoteProviderAuthorizationRejectsNilPolicyChecker(t *testing.T) {
	if checker, err := NewRemoteProviderAuthorizationChecker(nil); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("checker=%#v err=%v", checker, err)
	}
}

func TestRemoteProviderAuthorizationRequiresDistinctProviders(t *testing.T) {
	inventoryDocument, policyDocument := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	var document map[string]any
	if json.Unmarshal(policyDocument, &document) != nil {
		t.Fatal("decode")
	}
	document["verification_independence"] = "distinct_model"
	document["publication_minimum_independence"] = "distinct_model"
	policyDocument, _ = json.Marshal(document)
	inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	checker, _ := NewRemoteProviderAuthorizationChecker(policyChecker)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("state=%s", result.State())
	}
}

func TestRemoteProviderAuthorizationRejectsAliasedProviderAuthorities(t *testing.T) {
	for _, test := range []struct {
		name                         string
		sameEndpoint, sameCredential bool
	}{{"same endpoint", true, false}, {"same credential authority", false, true}, {"default port alias", false, false}} {
		t.Run(test.name, func(t *testing.T) {
			endpoints := []string{"https://one.example/v1", "https://two.example/v1"}
			if test.sameEndpoint {
				endpoints[1] = endpoints[0]
			}
			if test.name == "default port alias" {
				endpoints = []string{"https://one.example/v1", "https://one.example:443/v2"}
			}
			inventoryDocument, policyDocument := setupRuntimeDocuments(t, "private_remote", endpoints, 100000, false)
			if test.sameCredential {
				var document map[string]any
				_ = json.Unmarshal(policyDocument, &document)
				connections := document["connections"].([]any)
				first := connections[0].(map[string]any)["credential_environment"]
				connections[1].(map[string]any)["credential_environment"] = first
				policyDocument, _ = json.Marshal(document)
			}
			inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
			plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
			policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			checker, _ := NewRemoteProviderAuthorizationChecker(policyChecker)
			if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
				t.Fatalf("state=%s", result.State())
			}
		})
	}
}
