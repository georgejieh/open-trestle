package setup

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localInferenceFixtureFactory struct {
	calls, dispatches         int
	maxOutput                 []uint32
	inputTokens, outputTokens uint64
	err                       error
	failure                   gateway.RouteFailureClass
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
			dispatchers = append(dispatchers, localInferenceFailureDispatcher{connection.AdapterID(), dryRunIdentity("failure", connection.AdapterID()), f.failure})
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
	d.factory.maxOutput = append(d.factory.maxOutput, request.Authorization().MaxOutputTokens())
	if d.factory.outputTokens > 0 || d.factory.inputTokens > 0 {
		document := `{"schema_version":1,"verdicts":[]}`
		if strings.Contains(string(request.Request().Payload()), "candidate_generation") {
			document = `{"schema_version":1,"candidates":[]}`
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
	return d.setupDryRunDispatcher.DispatchRoute(ctx, request)
}

type localInferenceFailureDispatcher struct {
	adapter, identity string
	failure           gateway.RouteFailureClass
}

func (d localInferenceFailureDispatcher) AdapterID() string             { return d.adapter }
func (d localInferenceFailureDispatcher) ConfigurationIdentity() string { return d.identity }
func (d localInferenceFailureDispatcher) DispatchRoute(context.Context, gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	result, _ := gateway.NewFailedRouteDispatchResult(d.failure, gateway.RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
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
	remotePlan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
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
	}{{gateway.RouteFailureTimeout, CheckUnavailable}, {gateway.RouteFailureRateLimited, CheckUnavailable}, {gateway.RouteFailureInvalidResponse, CheckBlocked}, {gateway.RouteFailureAuthentication, CheckBlocked}} {
		factory := &localInferenceFixtureFactory{failure: test.failure}
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("%s=%s", test.failure.String(), result.State())
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
	for _, factory := range []*localInferenceFixtureFactory{{outputTokens: 257}, {inputTokens: 1025}} {
		checker, _ := NewLocalInferenceChecker(policyChecker, factory)
		if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked {
			t.Fatalf("result=%s", result.State())
		}
	}
}
