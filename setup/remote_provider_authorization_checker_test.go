package setup

import (
	"context"
	"errors"
	"testing"
)

func TestRemoteProviderAuthorizationIsBlockedForLocalProfile(t *testing.T) {
	inventoryDocument, policyDocument := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	inventory, policy := parseSetupRuntimeDocuments(t, inventoryDocument, policyDocument)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	checker, err := NewRemoteProviderAuthorizationChecker(policyChecker)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("state=%s", result.State())
	}
}
func TestRemoteProviderAuthorizationRejectsLocalOrUnsafeRemotePosture(t *testing.T) {
	for _, test := range []struct {
		profile   Profile
		zone      string
		endpoints []string
		cost      uint64
		logging   bool
	}{{ProfileLocalSingleNode, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false}} {
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

func TestRemoteProviderAuthorizationRejectsNilPolicyChecker(t *testing.T) {
	if checker, err := NewRemoteProviderAuthorizationChecker(nil); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("checker=%#v err=%v", checker, err)
	}
}
