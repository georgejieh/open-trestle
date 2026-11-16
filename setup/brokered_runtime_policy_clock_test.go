package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestSetupBrokeredUsesHostClockAndRechecksAfterPolicyReceipt(t *testing.T) {
	invDoc, polDoc := setupBrokeredDocumentsWithWitness(t, func(w *brokeredPrivacyFixture) {
		w.ValidFrom, w.ValidUntil = "2026-10-30T00:00:00Z", "2026-10-31T00:00:00Z"
	}, nil)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	clock := &brokeredSetupClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	checker, err := NewRuntimePolicyCheckerWithClock(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy), clock)
	if err != nil {
		t.Fatal(err)
	}
	remote, _ := NewRemoteProviderAuthorizationChecker(checker)
	if checker.Check(context.Background(), plan).State() != CheckPassed || remote.Check(context.Background(), plan).State() != CheckPassed {
		t.Fatal("current scope rejected")
	}
	plan = policyCheckedPlan(t, plan, checker)
	clock.at = time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	if checker.Check(context.Background(), plan).State() != CheckBlocked || remote.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("authority valid at excluded until boundary")
	}
	dry, _ := NewDryRunChecker(checker)
	if dry.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("policy receipt bypassed expiry")
	}
}

type brokeredSetupClock struct{ at time.Time }

func (c *brokeredSetupClock) Now() time.Time { return c.at }

func TestSetupBrokeredDoesNotWidenLegacyExactVerifierRemoteRule(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	inventory, _ := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
	var wire map[string]any
	if json.Unmarshal(polDoc, &wire) != nil {
		t.Fatal("decode")
	}
	records := map[string]string{}
	for _, observed := range inventory.Candidates() {
		r := observed.ResolvedRecord().RouteRegistryRecord()
		records[r.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = r.Identity()
	}
	wire["schema_version"] = 2
	wire["pinned_route_record_identity"] = records["adapter-a"]
	wire["verification_route_record_identity"] = records["adapter-b"]
	polDoc, _ = json.Marshal(wire)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	remote, _ := NewRemoteProviderAuthorizationChecker(checker)
	if checker.Check(context.Background(), plan).State() != CheckBlocked || remote.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("legacy v2 remote exact-verifier rule widened")
	}
}
