package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"testing"
)

func TestSetupBrokeredDirectVerifierLoggingBlockedBySharedLoop(t *testing.T) {
	invDoc, polDoc := setupBrokeredDocuments(t, nil)
	var invWire, polWire map[string]any
	if json.Unmarshal(invDoc, &invWire) != nil || json.Unmarshal(polDoc, &polWire) != nil {
		t.Fatal("decode")
	}
	invWire["routes"].([]any)[1].(map[string]any)["content_logging"] = "enabled"
	invDoc, _ = json.Marshal(invWire)
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
	if err != nil {
		t.Fatal(err)
	}
	polWire["inventory_identity"] = inventory.Identity()
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-b" {
			polWire["verification_route_record_identity"] = record.Identity()
		}
	}
	polDoc, _ = json.Marshal(polWire)
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(polDoc), inventory)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteProviderAuthorizationChecker(checker)
	if err != nil {
		t.Fatal(err)
	}
	if checker.Check(context.Background(), plan).State() != CheckBlocked || remote.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("shared logging guard bypassed")
	}
}
