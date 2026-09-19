package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
)

func policyCheckedPlan(t *testing.T, plan Plan, checker *RuntimePolicyChecker) Plan {
	t.Helper()
	receipt, err := newCheckReceipt(plan, CheckPolicyValidated, builtInCheckerIdentity(CheckPolicyValidated), CheckPassed, checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckPolicyValidated), checker.configurationIdentity, "valid"), RecoveryNone, plan.UpdatedAt().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	next, err := applyCheckReceipt(plan, receipt, plan.checkerCatalog)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
func TestDryRunCheckerExecutesIndependentNonPublishingRoutes(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	checker, err := NewDryRunChecker(policyChecker)
	if err != nil {
		t.Fatal(err)
	}
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckPassed || result.validate(CheckDryRunValidated) != nil {
		t.Fatalf("result=%#v", result)
	}
	if bytes.Contains([]byte(result.EvidenceIdentity()), []byte("127.0.0.1")) {
		t.Fatal("details leaked")
	}
}
func TestDryRunCheckerRequiresExactPassedPolicyReceipt(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	checker, _ := NewDryRunChecker(policyChecker)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("without policy=%s", result.State())
	}
	plan = policyCheckedPlan(t, plan, policyChecker)
	otherPlan, _ := NewPlan(ProfileLocalSingleNode, "tenant-b", "repo-b", "owner", setupTime(1))
	otherChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, otherPlan, inventory, policy))
	checker, _ = NewDryRunChecker(otherChecker)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("cross scope=%s", result.State())
	}
}
func TestDryRunFileCheckerReportsConfigurationLoss(t *testing.T) {
	root := t.TempDir()
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	invPath, polPath := filepath.Join(root, "routes.json"), filepath.Join(root, "policy.json")
	_ = os.WriteFile(invPath, invDoc, 0o600)
	_ = os.WriteFile(polPath, polDoc, 0o600)
	policyChecker, _ := NewRuntimePolicyFileChecker(invPath, polPath, approval)
	loadedInventory, loadedPolicy, loadedID, state := policyChecker.load(context.Background())
	if state != runtimePolicyLoadValid || !approval.validate(plan, loadedInventory, loadedPolicy) {
		t.Fatal("load")
	}
	policyChecker.configurationIdentity = loadedID
	plan = policyCheckedPlan(t, plan, policyChecker)
	checker, _ := NewDryRunChecker(policyChecker)
	_ = os.Remove(polPath)
	if result := checker.Check(context.Background(), plan); result.State() != CheckUnavailable {
		t.Fatalf("missing=%s", result.State())
	}
}

func TestDryRunCheckerSupportsEveryInferencePosture(t *testing.T) {
	tests := []struct {
		profile   Profile
		zone      string
		endpoints []string
		cost      uint64
	}{{ProfileLocalSingleNode, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0}, {ProfileAirGapped, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0}, {ProfileControlledHybrid, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000}, {ProfileKubernetesHA, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000}}
	for _, tt := range tests {
		t.Run(string(tt.profile), func(t *testing.T) {
			invDoc, polDoc := setupRuntimeDocuments(t, tt.zone, tt.endpoints, tt.cost, false)
			inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
			plan, _ := NewPlan(tt.profile, "tenant-a", "repo-a", "owner", setupTime(1))
			policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			plan = policyCheckedPlan(t, plan, policyChecker)
			checker, _ := NewDryRunChecker(policyChecker)
			first := checker.Check(context.Background(), plan)
			second := checker.Check(context.Background(), plan)
			if first.State() != CheckPassed || first.EvidenceIdentity() != second.EvidenceIdentity() {
				t.Fatalf("results=%#v %#v", first, second)
			}
		})
	}
}

func TestDryRunVerificationAdmissionRejectsWrongDocumentField(t *testing.T) {
	sourceRange, _ := evidence.NewSourceRange("setup-dry-run.go", 1, 1)
	snapshot, _ := reviewcore.NewReviewSnapshot("setup-dry-run", dryRunIdentity("revision"), []evidence.SourceRange{sourceRange})
	usage, _ := provider.NewRouteTokenUsage(1, 1, 0)
	candidatePart, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"candidates":[]}`))
	candidateResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{candidatePart}, usage)
	candidates, err := reviewcore.ParseCandidateBatch(candidateResponse, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongPart, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"results":[]}`))
	wrongResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{wrongPart}, usage)
	if batch, err := admitSetupDryRunVerification(wrongResponse, candidates); err == nil || batch.Identity() != "" {
		t.Fatal("malformed verification document admitted")
	}
}
