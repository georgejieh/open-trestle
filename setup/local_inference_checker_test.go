package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localInferenceFixtureFactory struct {
	calls, dispatches         int
	maxOutput                 []uint32
	records                   []string
	requests                  []provider.Request
	budgets                   []provider.ModelCostBudget
	inputTokens, outputTokens uint64
	err                       error
	failure                   gateway.RouteFailureClass
	safety                    gateway.RouteReplaySafety
}

func (f *localInferenceFixtureFactory) FactoryIdentity() string {
	return setupDigest("local-inference-factory")
}
func (f *localInferenceFixtureFactory) Build(ctx context.Context, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error) {
	f.calls++
	if f.err != nil {
		return gateway.RouteDispatcherCatalog{}, f.err
	}
	authorities, ok := setupRouteConnectionAuthorities(inventory, policy)
	if !ok {
		return gateway.RouteDispatcherCatalog{}, errors.New("authority")
	}
	dispatchers := make([]gateway.RouteDispatcher, 0, len(authorities))
	for _, connection := range policy.Connections() {
		authority, found := authorities[connection.AdapterID()]
		if !found {
			return gateway.RouteDispatcherCatalog{}, errors.New("missing")
		}
		if f.failure != 0 {
			dispatchers = append(dispatchers, localInferenceFailureDispatcher{connection.AdapterID(), dryRunIdentity("failure", connection.AdapterID()), f.failure, f.safety})
		} else {
			dispatchers = append(dispatchers, countingLocalInferenceDispatcher{setupDryRunDispatcher{authority, dryRunIdentity("local-inference-fixture", connection.AdapterID())}, f})
		}
	}
	return gateway.NewRouteDispatcherCatalog(dispatchers)
}

type countingLocalInferenceDispatcher struct {
	setupDryRunDispatcher
	factory *localInferenceFixtureFactory
}

func (d countingLocalInferenceDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	d.factory.dispatches++
	d.factory.records = append(d.factory.records, request.Authorization().RouteRecordIdentity())
	d.factory.maxOutput = append(d.factory.maxOutput, request.Authorization().MaxOutputTokens())
	d.factory.requests = append(d.factory.requests, request.Request())
	d.factory.budgets = append(d.factory.budgets, request.Authorization().CostBudget())
	document := `{"schema_version":1,"verdicts":[]}`
	if _, err := review.SanitizedCandidatePayload(request.Request(), request.Authorization().ReviewScopeIdentity()); err == nil || strings.Contains(string(request.Request().Payload()), "candidate_generation") {
		document = `{"schema_version":2,"candidates":[]}`
	}
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	inputTokens, outputTokens := d.factory.inputTokens, d.factory.outputTokens
	if inputTokens == 0 {
		inputTokens = 1
	}
	if outputTokens == 0 {
		outputTokens = 1
	}
	usage, _ := provider.NewRouteTokenUsage(inputTokens, outputTokens, 0)
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	result, _ := gateway.NewSuccessfulRouteDispatchResult(response)
	return result
}

type localInferenceFailureDispatcher struct {
	adapter, identity string
	failure           gateway.RouteFailureClass
	safety            gateway.RouteReplaySafety
}

func (d localInferenceFailureDispatcher) AdapterID() string             { return d.adapter }
func (d localInferenceFailureDispatcher) ConfigurationIdentity() string { return d.identity }
func (d localInferenceFailureDispatcher) DispatchRoute(context.Context, gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	safety := d.safety
	if safety == 0 {
		safety = gateway.RouteReplayNoSideEffect
	}
	result, _ := gateway.NewFailedRouteDispatchResult(d.failure, safety, provider.NewUnknownRouteTokenUsage(), 0)
	return result
}

func TestLocalInferenceCheckerRunsOneIndependentPairAfterPolicyApproval(t *testing.T) {
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
	first := checker.Check(context.Background(), plan)
	second := checker.Check(context.Background(), plan)
	if first.State() != CheckPassed || first.validate(CheckLocalInferenceValidated) != nil || first.EvidenceIdentity() != second.EvidenceIdentity() || factory.calls != 2 || factory.dispatches != 4 || len(factory.maxOutput) != 4 {
		t.Fatalf("results=%#v %#v builds=%d dispatches=%d", first, second, factory.calls, factory.dispatches)
	}
	for _, limit := range factory.maxOutput {
		if limit != 256 {
			t.Fatalf("output limit=%d", limit)
		}
	}
}
func TestLocalInferenceCheckerUsesExactV2Pair(t *testing.T) {
	for _, state := range []string{"ready", "unhealthy verifier", "non-independent verifier", "missing generation pin"} {
		t.Run(state, func(t *testing.T) {
			invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://127.0.0.1:11435/v1", "http://127.0.0.1:11436/v1"}, 0, false)
			var inventoryWire map[string]any
			if err := json.Unmarshal(invDoc, &inventoryWire); err != nil {
				t.Fatal(err)
			}
			routes := inventoryWire["routes"].([]any)
			switch state {
			case "unhealthy verifier":
				routes[2].(map[string]any)["health"] = "unhealthy"
			case "non-independent verifier":
				routes[2].(map[string]any)["provider_id"] = "provider-b"
			}
			invDoc, err := json.Marshal(inventoryWire)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
			if err != nil {
				t.Fatal(err)
			}
			records := map[string]string{}
			for _, candidate := range inventory.Candidates() {
				record := candidate.ResolvedRecord().RouteRegistryRecord()
				records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
			}
			var policyWire map[string]any
			if err := json.Unmarshal(polDoc, &policyWire); err != nil {
				t.Fatal(err)
			}
			policyWire["schema_version"] = 2
			policyWire["inventory_identity"] = inventory.Identity()
			policyWire["pinned_route_record_identity"] = records["adapter-b"]
			policyWire["verification_route_record_identity"] = records["adapter-c"]
			policyWire["preferred_route_record_identities"] = []string{records["adapter-a"]}
			if state == "missing generation pin" {
				policyWire["pinned_route_record_identity"] = ""
			}
			polDoc, err = json.Marshal(policyWire)
			if err != nil {
				t.Fatal(err)
			}
			inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
			plan, err := NewCurrentPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
			if err != nil {
				t.Fatal(err)
			}
			policyChecker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			if err != nil {
				t.Fatal(err)
			}
			want := CheckPassed
			if state != "ready" {
				want = CheckBlocked
			}
			if result := policyChecker.Check(context.Background(), plan); result.State() != want {
				t.Fatalf("policy=%s want=%s", result.State(), want)
			}
			factory := &localInferenceFixtureFactory{}
			checker, err := NewLocalInferenceChecker(policyChecker, factory)
			if err != nil {
				t.Fatal(err)
			}
			if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || factory.calls != 0 {
				t.Fatalf("without receipt=%s builds=%d", result.State(), factory.calls)
			}
			plan = policyCheckedPlan(t, plan, policyChecker)
			if result := checker.Check(context.Background(), plan); result.State() != want {
				t.Fatalf("inference=%s want=%s", result.State(), want)
			}
			if state != "ready" {
				if factory.calls != 0 || factory.dispatches != 0 {
					t.Fatalf("invalid selected pair builds=%d dispatches=%d", factory.calls, factory.dispatches)
				}
				return
			}
			if factory.calls != 1 || factory.dispatches != 2 || len(factory.records) != 2 || factory.records[0] != records["adapter-b"] || factory.records[1] != records["adapter-c"] {
				t.Fatalf("builds=%d dispatches=%d selected records=%v", factory.calls, factory.dispatches, factory.records)
			}
		})
	}
}

func TestLocalInferenceCheckerNeverBuildsBeforeExactLocalPolicyReceipt(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	factory := &localInferenceFixtureFactory{}
	checker, _ := NewLocalInferenceChecker(policyChecker, factory)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || factory.calls != 0 {
		t.Fatalf("without policy=%s calls=%d", result.State(), factory.calls)
	}
	remoteInv, remotePol := setupRuntimeDocuments(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"}, 100000, false)
	remoteInventory, remotePolicy := parseSetupRuntimeDocuments(t, remoteInv, remotePol)
	remotePlan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	remoteChecker, _ := NewRuntimePolicyChecker(remoteInventory, remotePolicy, setupRuntimeApproval(t, remotePlan, remoteInventory, remotePolicy))
	remotePlan = policyCheckedPlan(t, remotePlan, remoteChecker)
	checker, _ = NewLocalInferenceChecker(remoteChecker, factory)
	if result := checker.Check(context.Background(), remotePlan); result.State() != CheckBlocked || factory.calls != 0 {
		t.Fatalf("remote=%s calls=%d", result.State(), factory.calls)
	}
}
func TestLocalInferenceCheckerClassifiesFactoryFailureAndRejectsTypedNil(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	factory := &localInferenceFixtureFactory{err: errors.New("factory")}
	checker, _ := NewLocalInferenceChecker(policyChecker, factory)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("factory=%s", result.State())
	}
	var nilFactory *localInferenceFixtureFactory
	if checker, err := NewLocalInferenceChecker(policyChecker, nilFactory); !errors.Is(err, ErrInvalidCheckerRuntime) || checker != nil {
		t.Fatalf("nil=%#v %v", checker, err)
	}
}

func TestLocalInferenceCheckerSeparatesTransientAndInvalidResponses(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	for _, test := range []struct {
		failure gateway.RouteFailureClass
		want    CheckState
	}{{gateway.RouteFailureTimeout, CheckUnavailable}, {gateway.RouteFailureRateLimited, CheckUnavailable}, {gateway.RouteFailureInvalidResponse, CheckBlocked}, {gateway.RouteFailureAuthentication, CheckBlocked}, {gateway.RouteFailureRequestRejected, CheckBlocked}} {
		factory := &localInferenceFixtureFactory{failure: test.failure}
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("%s=%s", test.failure.String(), result.State())
		}
	}
}

// A probe the provider refused keeps the refused check states and reports the
// refusal's closed class, so setup can name the same reason a review does. A
// failure before the request was sent, or a probe that passed, reports none.
func TestLocalInferenceCheckerReportsTheProviderAnsweredFailure(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	for _, test := range []struct {
		failure  gateway.RouteFailureClass
		safety   gateway.RouteReplaySafety
		state    CheckState
		reported bool
	}{
		{gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect, CheckBlocked, true},
		{gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect, CheckBlocked, true},
		{gateway.RouteFailureModelRetired, gateway.RouteReplayNoSideEffect, CheckBlocked, true},
		// A rejected request is refused, not an unavailable server.
		{gateway.RouteFailureRequestRejected, gateway.RouteReplayNoSideEffect, CheckBlocked, true},
		{gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, CheckUnavailable, true},
		{gateway.RouteFailureAuthentication, gateway.RouteReplayNotDispatched, CheckBlocked, false},
	} {
		factory := &localInferenceFixtureFactory{failure: test.failure, safety: test.safety}
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if failure, ok := checker.ProbeFailure(); ok || failure != 0 {
			t.Fatal("a checker that never ran reported a probe failure")
		}
		if result := checker.Check(context.Background(), plan); result.State() != test.state {
			t.Fatalf("%s=%s", test.failure, result.State())
		}
		failure, ok := checker.ProbeFailure()
		if ok != test.reported || ok && failure != test.failure {
			t.Fatalf("%s reported (%s, %t)", test.failure, failure, ok)
		}
		factory.failure = 0
		if result := checker.Check(context.Background(), plan); result.State() != CheckPassed {
			t.Fatalf("recovered probe = %s", result.State())
		}
		if failure, ok := checker.ProbeFailure(); ok || failure != 0 {
			t.Fatal("a passed check kept an earlier probe failure")
		}
	}
}

type mutableInferenceFactory struct {
	localInferenceFixtureFactory
	identity string
}

func (f *mutableInferenceFactory) FactoryIdentity() string { return f.identity }
func TestLocalInferenceCheckerRejectsFactoryIdentityMutationBeforeBuild(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	factory := &mutableInferenceFactory{identity: setupDigest("first")}
	checker, _ := NewLocalInferenceChecker(policyChecker, factory)
	factory.identity = setupDigest("second")
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || factory.calls != 0 {
		t.Fatalf("result=%s calls=%d", result.State(), factory.calls)
	}
}

func TestLocalInferenceCheckerRejectsReportedUsageBeyondAuthorization(t *testing.T) {
	invDoc, polDoc := setupRuntimeDocuments(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}, 0, false)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	policyChecker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	plan = policyCheckedPlan(t, plan, policyChecker)
	// Reported input above every probe's reservation is refused; the exact
	// reservation boundary is covered by the reservation tests.
	for _, factory := range []*localInferenceFixtureFactory{{outputTokens: 257}, {inputTokens: 1 << 20}} {
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
			t.Fatalf("result=%s", result.State())
		}
	}
}
