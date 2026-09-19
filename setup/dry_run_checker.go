package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const setupDryRunTimeout = 5 * time.Second

// DryRunChecker executes a bounded provider-neutral review routing fixture with local deterministic dispatchers. It has no publisher, source writer, validation process, network client, or credential resolver.
type DryRunChecker struct {
	policy                *RuntimePolicyChecker
	configurationIdentity string
}

// NewDryRunChecker binds the exact runtime policy checker used by the required policy approval.
func NewDryRunChecker(policy *RuntimePolicyChecker) (*DryRunChecker, error) {
	if policy == nil || !validRuntimePolicyApproval(policy.approval) || policy.configurationIdentity == "" {
		return nil, ErrInvalidCheckerRuntime
	}
	identity := checkerConfigIdentity(CheckDryRunValidated, policy.configurationIdentity+"\x00"+policy.approval.Identity())
	return &DryRunChecker{policy: policy, configurationIdentity: identity}, nil
}
func (c *DryRunChecker) Key() CheckKey           { return CheckDryRunValidated }
func (c *DryRunChecker) CheckerIdentity() string { return builtInCheckerIdentity(CheckDryRunValidated) }
func (c *DryRunChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		inventory, policy, loadedIdentity, loadState := c.policy.load(ctx)
		if loadedIdentity != "" {
			configurationIdentity = checkerConfigIdentity(CheckDryRunValidated, loadedIdentity+"\x00"+c.policy.approval.Identity())
		}
		switch loadState {
		case runtimePolicyLoadUnavailable:
			state, outcome = CheckUnavailable, "configuration_unavailable"
		case runtimePolicyLoadBlocked:
			outcome = "configuration_invalid"
		case runtimePolicyLoadValid:
			if !c.policy.approval.validate(plan, inventory, policy) || !runtimePolicyMatchesSetup(plan, inventory, policy) || !passedPolicyReceiptMatches(plan, loadedIdentity) {
				outcome = "policy_mismatch"
				break
			}
			bounded, cancel := context.WithTimeout(ctx, setupDryRunTimeout)
			executionIdentity, err := executeSetupDryRun(bounded, plan, inventory, policy)
			cancel()
			if err == nil {
				state, outcome = CheckPassed, "valid"
				configurationIdentity = checkerConfigIdentity(CheckDryRunValidated, loadedIdentity+"\x00"+c.policy.approval.Identity()+"\x00"+executionIdentity)
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				state, outcome = CheckUnavailable, "execution_unavailable"
			} else {
				outcome = "execution_blocked"
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckDryRunValidated), configurationIdentity, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckDryRunValidated, state, evidence)
}
func passedPolicyReceiptMatches(plan Plan, configurationIdentity string) bool {
	index, found := planRequirementIndex(plan, CheckPolicyValidated)
	if !found || plan.requirements[index].state != CheckPassed {
		return false
	}
	for i := len(plan.receipts) - 1; i >= 0; i-- {
		receipt := plan.receipts[i]
		if receipt.key != CheckPolicyValidated {
			continue
		}
		expected := checkerEvidenceIdentity(receipt.planIdentity, builtInCheckerIdentity(CheckPolicyValidated), configurationIdentity, "valid")
		return receipt.state == CheckPassed && receipt.checkerIdentity == builtInCheckerIdentity(CheckPolicyValidated) && receipt.evidenceIdentity == expected && plan.requirements[index].receiptIdentity == receipt.identity
	}
	return false
}

type setupDryRunDispatcher struct {
	authority             setupRouteConnectionAuthority
	configurationIdentity string
}

func (d setupDryRunDispatcher) AdapterID() string             { return d.authority.adapterID }
func (d setupDryRunDispatcher) ConfigurationIdentity() string { return d.configurationIdentity }
func (d setupDryRunDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	if ctx == nil || ctx.Err() != nil || request.Validate() != nil || !d.authority.matches(request.Authorization().RouteReference(), request.Authorization().ContentLoggingMode()) {
		return failedSetupDryRunDispatch()
	}
	document := `{"schema_version":1,"verdicts":[]}`
	if strings.Contains(string(request.Request().Payload()), "candidate_generation") {
		document = `{"schema_version":1,"candidates":[]}`
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	if err != nil {
		return failedSetupDryRunDispatch()
	}
	usage, err := provider.NewRouteTokenUsage(1, 1, 0)
	if err != nil {
		return failedSetupDryRunDispatch()
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	if err != nil {
		return failedSetupDryRunDispatch()
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		return failedSetupDryRunDispatch()
	}
	return result
}
func failedSetupDryRunDispatch() gateway.RouteDispatchResult {
	result, _ := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
	return result
}
func executeSetupDryRun(ctx context.Context, plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", context.Canceled
	}
	scope, err := audit.NewReviewScope(plan.TenantID(), plan.RepositoryID(), "setup-dry-run")
	if err != nil {
		return "", err
	}
	authorities, validAuthorities := setupRouteConnectionAuthorities(inventory, policy)
	if !validAuthorities {
		return "", ErrInvalidCheckerRuntime
	}
	dispatchers := make([]gateway.RouteDispatcher, 0, len(policy.Connections()))
	for _, connection := range policy.Connections() {
		authority, found := authorities[connection.AdapterID()]
		if !found {
			return "", ErrInvalidCheckerRuntime
		}
		identity := dryRunIdentity("dispatcher", authority.zone.String(), authority.providerID, authority.adapterID, authority.connectionID, authority.logging.String(), connection.Endpoint(), connection.CredentialIdentity(), policy.Identity())
		dispatchers = append(dispatchers, setupDryRunDispatcher{authority, identity})
	}
	catalog, err := gateway.NewRouteDispatcherCatalog(dispatchers)
	if err != nil {
		return "", err
	}
	sourceRange, err := evidence.NewSourceRange("setup-dry-run.go", 1, 1)
	if err != nil {
		return "", err
	}
	snapshot, err := reviewcore.NewReviewSnapshot("setup-dry-run", dryRunIdentity("revision", plan.RootIdentity()), []evidence.SourceRange{sourceRange})
	if err != nil {
		return "", err
	}
	generationRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-dry-run","task":"candidate_generation"}`))
	if err != nil {
		return "", err
	}
	generationAuthorization, err := authorizeSetupDryRun(scope, generationRequest, inventory, policy, inventory.Candidates())
	if err != nil {
		return "", err
	}
	var candidates reviewcore.CandidateBatch
	generation, err := executeSetupDryRunRoute(ctx, catalog, generationRequest, generationAuthorization, gateway.RouteOutputCandidateBatch, func(response provider.Response) (string, error) {
		batch, admitErr := reviewcore.ParseCandidateBatch(response, snapshot, nil)
		if admitErr == nil {
			candidates = batch
		}
		return batch.Identity(), admitErr
	})
	if err != nil {
		return "", err
	}
	independent := make([]gateway.ObservedRouteCandidate, 0)
	for _, candidate := range inventory.Candidates() {
		if gateway.VerifyIndependentRouteCandidate(policy.Independence(), generationAuthorization, candidate) == nil {
			independent = append(independent, candidate)
		}
	}
	verificationRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-dry-run","task":"independent_verification"}`))
	if err != nil {
		return "", err
	}
	verificationAuthorization, err := authorizeSetupDryRun(scope, verificationRequest, inventory, policy, independent)
	if err != nil {
		return "", err
	}
	if err = gateway.VerifyIndependentRouteAuthorizations(policy.Independence(), generationAuthorization, verificationAuthorization); err != nil {
		return "", err
	}
	var verdicts reviewcore.VerificationBatch
	verification, err := executeSetupDryRunRoute(ctx, catalog, verificationRequest, verificationAuthorization, gateway.RouteOutputVerificationBatch, func(response provider.Response) (string, error) {
		batch, admitErr := admitSetupDryRunVerification(response, candidates)
		if admitErr == nil {
			verdicts = batch
		}
		return batch.Identity(), admitErr
	})
	if err != nil {
		return "", err
	}
	independence, err := gateway.VerifyIndependentRouteAttempts(policy.Independence(), generation.Authorization(), generation.Outcome(), verification.Authorization(), verification.Outcome())
	if err != nil {
		return "", err
	}
	return dryRunIdentity("execution", plan.RootIdentity(), inventory.Identity(), policy.Identity(), generation.Identity(), candidates.Identity(), verification.Identity(), verdicts.Identity(), independence.Identity(), "publication_attempts:0", "source_mutations:0", "dynamic_validation_attempts:0"), nil
}
func authorizeSetupDryRun(scope audit.ReviewScope, request provider.Request, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, candidates []gateway.ObservedRouteCandidate) (gateway.RouteAttemptAuthorization, error) {
	return authorizeSetupRoute(scope, request, inventory, policy, candidates, policy.Requirements(), policy.Budget())
}
func authorizeSetupRoute(scope audit.ReviewScope, request provider.Request, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, candidates []gateway.ObservedRouteCandidate, requirements provider.ModelRequirements, budget provider.ModelCostBudget) (gateway.RouteAttemptAuthorization, error) {
	routing, err := gateway.NewReviewRoutingInput(scope, request, requirements, policy.Constraints())
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	eligibility, err := gateway.FilterEligibleRoutes(routing, budget, inventory.RegistryRevision(), candidates)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	eligible := map[string]bool{}
	for _, candidate := range eligibility.EligibleRoutes() {
		eligible[candidate.ResolvedRecord().RouteRegistryRecord().Identity()] = true
	}
	observations := make([]provider.RoutePerformanceObservation, 0, len(eligible))
	for _, observation := range inventory.PerformanceObservations() {
		if eligible[observation.RecordIdentity()] {
			observations = append(observations, observation)
		}
	}
	ranking, err := gateway.RankEligibleRoutes(eligibility, policy.Ranking(), inventory.PerformanceRevision(), observations)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	selection, err := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	return gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
}

type setupDryRunAdmission func(provider.Response) (string, error)

func executeSetupDryRunRoute(ctx context.Context, catalog gateway.RouteDispatcherCatalog, request provider.Request, authorization gateway.RouteAttemptAuthorization, kind gateway.RouteOutputKind, admit setupDryRunAdmission) (gateway.RouteExecutionRecord, error) {
	result, err := gateway.DispatchAuthorizedRouteFromCatalog(ctx, catalog, authorization, request)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	outcome, err := gateway.NewRouteAttemptOutcomeFromDispatch(authorization, result, 1)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	if admit == nil {
		return gateway.RouteExecutionRecord{}, ErrInvalidCheckerRuntime
	}
	artifactIdentity, err := admit(result.Response())
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	contextIdentity := dryRunIdentity("context", request.Identity())
	output, err := gateway.NewSuccessfulRouteOutputReceipt(kind, contextIdentity, artifactIdentity, request, authorization, outcome)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	return gateway.NewRouteExecutionRecord(authorization, outcome, reconciliation, output)
}
func admitSetupDryRunVerification(response provider.Response, candidates reviewcore.CandidateBatch) (reviewcore.VerificationBatch, error) {
	return reviewcore.ParseVerificationBatch(response, candidates, nil)
}
func dryRunIdentity(values ...string) string {
	encoded, _ := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Values   []string `json:"values"`
	}{"open-trestle/setup-dry-run-evidence", 1, values})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (c *DryRunChecker) String() string   { return "setup non-publishing dry run checker" }
func (c *DryRunChecker) GoString() string { return "setup.DryRunChecker{<redacted>}" }
func (c *DryRunChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
