package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// The probe must reserve what each request sends, as review planning does, and
// accept reported input up to that reservation rather than a fixed 1,024.
func TestLocalInferenceProbeReservesWhatEachRequestSends(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	factory := &localInferenceFixtureFactory{}
	checker, err := NewLocalInferenceChecker(policyChecker, factory)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || len(factory.budgets) != 2 {
		t.Fatalf("result=%s dispatches=%d", result.State(), len(factory.budgets))
	}
	declared, err := provider.NewModelCostBudget(512, 256, 0)
	if err != nil {
		t.Fatal(err)
	}
	least, most := ^uint32(0), uint32(0)
	for i, budget := range factory.budgets {
		want, err := review.ModelRequestBudget(factory.requests[i], declared)
		if err != nil || budget != want || budget.EstimatedInputTokens() <= 1024 {
			t.Fatalf("probe %d reserved %d input, want its estimate %d", i, budget.EstimatedInputTokens(), want.EstimatedInputTokens())
		}
		least, most = min(least, budget.EstimatedInputTokens()), max(most, budget.EstimatedInputTokens())
	}
	for _, tc := range []struct {
		input uint64
		state CheckState
	}{{uint64(least), CheckPassed}, {uint64(most) + 1, CheckBlocked}} {
		factory := &localInferenceFixtureFactory{inputTokens: tc.input}
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if result := checker.Check(context.Background(), plan); result.State() != tc.state {
			t.Fatalf("reported input %d: result=%s, want %s", tc.input, result.State(), tc.state)
		}
	}
}

// Under the local structured-output transport the real adapter also checks the
// serialized response_format, so the probe must reserve it to be dispatched.
func TestLocalInferenceProbeRunsOverTheStructuredOutputTransport(t *testing.T) {
	for _, runtime := range namedLocalRuntimes {
		t.Run(runtime.name, func(t *testing.T) {
			var calls, formats atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var wire map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Error(err)
				}
				role := "generation"
				if calls.Add(1) == 2 {
					role = "verification"
				}
				if bytes.Contains(wire["response_format"], []byte(`"open_trestle_review"`)) {
					formats.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(namedLocalDocument(t, runtime.name, role+".response.json"))
			}))
			defer server.Close()
			inventory, policy := namedLocalConfigurationWith(t, runtime.name, server.URL+"/v1", true, func(template map[string]any) {
				template["schema_version"] = 6
				for _, connection := range template["connections"].([]any) {
					connection.(map[string]any)["local_structured_output"] = true
				}
			})
			plan, err := NewCurrentPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
			if err != nil {
				t.Fatal(err)
			}
			policyChecker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			if err != nil {
				t.Fatal(err)
			}
			plan = policyCheckedPlan(t, plan, policyChecker)
			checker, err := NewLocalInferenceChecker(policyChecker, namedLocalInferenceFactory{namedLocalCatalog(t, inventory, policy)})
			if err != nil {
				t.Fatal(err)
			}
			if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || calls.Load() != 2 || formats.Load() != 2 {
				t.Fatalf("state=%s calls=%d schema-bound calls=%d", result.State(), calls.Load(), formats.Load())
			}
		})
	}
}

// The dry run reserves what its requests send even when the policy declares a
// smaller input estimate.
func TestDryRunReservesWhatEachRequestSends(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	polDoc = bytes.Replace(polDoc, []byte(`"estimated_input_tokens":1000`), []byte(`"estimated_input_tokens":1`), 1)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	if policy.Budget().EstimatedInputTokens() != 1 {
		t.Fatal("fixture policy does not declare a nominal estimate")
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "setup-dry-run")
	if err != nil {
		t.Fatal(err)
	}
	generation, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-dry-run","task":"candidate_generation"}`))
	if err != nil {
		t.Fatal(err)
	}
	verification, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-dry-run","task":"independent_verification"}`))
	if err != nil {
		t.Fatal(err)
	}
	generationAuthorization, err := authorizeSetupDryRun(scope, generation, inventory, policy, inventory.Candidates())
	if err != nil {
		t.Fatal(err)
	}
	verificationAuthorization, err := authorizeSetupVerification(scope, verification, inventory, policy, generationAuthorization, policy.Requirements(), policy.Budget())
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		request provider.Request
		got     provider.ModelCostBudget
	}{"generation": {generation, generationAuthorization.CostBudget()}, "verification": {verification, verificationAuthorization.CostBudget()}} {
		want, err := review.ModelRequestBudget(tc.request, policy.Budget())
		if err != nil || tc.got != want || uint64(tc.got.EstimatedInputTokens()) != uint64(len(tc.request.Payload()))+256 {
			t.Fatalf("%s dry run reserved %d input, want %d", name, tc.got.EstimatedInputTokens(), want.EstimatedInputTokens())
		}
	}
	if !strings.Contains(string(generation.Payload()), "setup-dry-run") {
		t.Fatal("fixture is not the dry run request")
	}
}
