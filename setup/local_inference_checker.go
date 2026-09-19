package setup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const (
	setupLocalInferenceTimeout              = 90 * time.Second
	setupLocalInferenceEstimatedInputTokens = 512
	setupLocalInferenceMaximumInputTokens   = 1024
	setupLocalInferenceMaximumOutputTokens  = 256
)

var errLocalInferenceUnavailable = errors.New("local inference unavailable")

// LocalInferenceDispatcherFactory constructs exact request-time local adapters after policy approval.
type LocalInferenceDispatcherFactory interface {
	FactoryIdentity() string
	Build(context.Context, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error)
}

// LocalInferenceChecker sends one bounded candidate request and one independently routed verification request to approved local adapters.
type LocalInferenceChecker struct {
	policy                                 *RuntimePolicyChecker
	factory                                LocalInferenceDispatcherFactory
	factoryIdentity, configurationIdentity string
}

// NewLocalInferenceChecker binds an exact policy authority and adapter factory without resolving credentials or contacting an endpoint.
func NewLocalInferenceChecker(policy *RuntimePolicyChecker, factory LocalInferenceDispatcherFactory) (*LocalInferenceChecker, error) {
	if policy == nil || nilSetupInterface(factory) || !validRuntimePolicyApproval(policy.approval) || policy.configurationIdentity == "" || !nonzeroSetupDigest(factory.FactoryIdentity()) {
		return nil, ErrInvalidCheckerRuntime
	}
	factoryIdentity := factory.FactoryIdentity()
	identity := checkerConfigIdentity(CheckLocalInferenceValidated, policy.configurationIdentity+"\x00"+policy.approval.Identity()+"\x00"+factoryIdentity)
	return &LocalInferenceChecker{policy: policy, factory: factory, factoryIdentity: factoryIdentity, configurationIdentity: identity}, nil
}
func (c *LocalInferenceChecker) Key() CheckKey { return CheckLocalInferenceValidated }
func (c *LocalInferenceChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckLocalInferenceValidated)
}
func (c *LocalInferenceChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		if c.factory.FactoryIdentity() != c.factoryIdentity {
			evidenceIdentity := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckLocalInferenceValidated), configurationIdentity, "dispatcher_invalid")
			return NewFailedCheckResult(CheckLocalInferenceValidated, CheckBlocked, evidenceIdentity)
		}
		inventory, policy, loadedIdentity, loadState := c.policy.load(ctx)
		if loadedIdentity != "" {
			configurationIdentity = checkerConfigIdentity(CheckLocalInferenceValidated, loadedIdentity+"\x00"+c.policy.approval.Identity()+"\x00"+c.factoryIdentity)
		}
		switch loadState {
		case runtimePolicyLoadUnavailable:
			state, outcome = CheckUnavailable, "configuration_unavailable"
		case runtimePolicyLoadBlocked:
			outcome = "configuration_invalid"
		case runtimePolicyLoadValid:
			if plan.Posture().Inference() != InferenceLocalOnly || !c.policy.approval.validate(plan, inventory, policy) || !runtimePolicyMatchesSetup(plan, inventory, policy) || !passedPolicyReceiptMatches(plan, loadedIdentity) {
				outcome = "policy_mismatch"
				break
			}
			bounded, cancel := context.WithTimeout(ctx, setupLocalInferenceTimeout)
			catalog, err := c.factory.Build(bounded, inventory, policy)
			if err == nil && localInferenceCatalogMatches(catalog, policy) && c.factory.FactoryIdentity() == c.factoryIdentity {
				configurationIdentity = checkerConfigIdentity(CheckLocalInferenceValidated, loadedIdentity+"\x00"+c.policy.approval.Identity()+"\x00"+c.factoryIdentity+"\x00"+catalog.Identity())
				var execution string
				execution, err = executeSetupLocalInference(bounded, plan, inventory, policy, catalog)
				if err == nil {
					state, outcome = CheckPassed, "valid"
					configurationIdentity = checkerConfigIdentity(CheckLocalInferenceValidated, configurationIdentity+"\x00"+execution)
				} else if errors.Is(err, errLocalInferenceUnavailable) {
					state, outcome = CheckUnavailable, "execution_unavailable"
				} else {
					outcome = "execution_blocked"
				}
			} else {
				outcome = "dispatcher_invalid"
			}
			cancel()
		}
	}
	evidenceIdentity := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckLocalInferenceValidated), configurationIdentity, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidenceIdentity)
	}
	return NewFailedCheckResult(CheckLocalInferenceValidated, state, evidenceIdentity)
}

func localInferenceCatalogMatches(catalog gateway.RouteDispatcherCatalog, policy runtimeconfig.RuntimePolicy) bool {
	if catalog.Validate() != nil || policy.Validate() != nil || catalog.Len() != len(policy.Connections()) {
		return false
	}
	expected := map[string]bool{}
	for _, connection := range policy.Connections() {
		expected[connection.AdapterID()] = true
	}
	for _, adapter := range catalog.AdapterIDs() {
		if !expected[adapter] {
			return false
		}
		delete(expected, adapter)
	}
	return len(expected) == 0
}

func executeSetupLocalInference(ctx context.Context, plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, catalog gateway.RouteDispatcherCatalog) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", errLocalInferenceUnavailable
	}
	scope, err := audit.NewReviewScope(plan.TenantID(), plan.RepositoryID(), "setup-local-inference")
	if err != nil {
		return "", err
	}
	sourceRange, err := evidence.NewSourceRange("setup-local-inference.go", 1, 1)
	if err != nil {
		return "", err
	}
	snapshot, err := reviewcore.NewReviewSnapshot("setup-local-inference", dryRunIdentity("local-inference-revision", plan.RootIdentity()), []evidence.SourceRange{sourceRange})
	if err != nil {
		return "", err
	}
	probeBudget, err := provider.NewModelCostBudget(setupLocalInferenceEstimatedInputTokens, setupLocalInferenceMaximumOutputTokens, 0)
	if err != nil {
		return "", err
	}
	probeRequirements, err := provider.NewModelRequirements(setupLocalInferenceMaximumInputTokens, setupLocalInferenceMaximumOutputTokens, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		return "", err
	}
	candidateRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-local-inference-probe","schema_version":1,"task":"candidate_generation","instruction":"Return only this exact JSON object with no markdown or extra fields.","required_output":{"schema_version":1,"candidates":[]}}`))
	if err != nil {
		return "", err
	}
	candidateAuthorization, err := authorizeSetupRoute(scope, candidateRequest, inventory, policy, inventory.Candidates(), probeRequirements, probeBudget)
	if err != nil {
		return "", err
	}
	var candidates reviewcore.CandidateBatch
	generation, err := executeSetupLocalInferenceRoute(ctx, catalog, candidateRequest, candidateAuthorization, gateway.RouteOutputCandidateBatch, func(response provider.Response) (string, error) {
		batch, parseErr := reviewcore.ParseCandidateBatch(response, snapshot, nil)
		if parseErr != nil || len(batch.Findings()) != 0 {
			return "", ErrInvalidCheckerRuntime
		}
		candidates = batch
		return batch.Identity(), nil
	})
	if err != nil {
		return "", err
	}
	independent := make([]gateway.ObservedRouteCandidate, 0)
	for _, candidate := range inventory.Candidates() {
		if gateway.VerifyIndependentRouteCandidate(policy.Independence(), candidateAuthorization, candidate) == nil {
			independent = append(independent, candidate)
		}
	}
	verificationRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"open-trestle/setup-local-inference-probe","schema_version":1,"task":"independent_verification","instruction":"Return only this exact JSON object with no markdown or extra fields.","required_output":{"schema_version":1,"verdicts":[]}}`))
	if err != nil {
		return "", err
	}
	verificationAuthorization, err := authorizeSetupRoute(scope, verificationRequest, inventory, policy, independent, probeRequirements, probeBudget)
	if err != nil {
		return "", err
	}
	if err = gateway.VerifyIndependentRouteAuthorizations(policy.Independence(), candidateAuthorization, verificationAuthorization); err != nil {
		return "", err
	}
	var verdicts reviewcore.VerificationBatch
	verification, err := executeSetupLocalInferenceRoute(ctx, catalog, verificationRequest, verificationAuthorization, gateway.RouteOutputVerificationBatch, func(response provider.Response) (string, error) {
		batch, parseErr := reviewcore.ParseVerificationBatch(response, candidates, nil)
		if parseErr != nil || len(batch.Results()) != 0 {
			return "", ErrInvalidCheckerRuntime
		}
		verdicts = batch
		return batch.Identity(), nil
	})
	if err != nil {
		return "", err
	}
	independence, err := gateway.VerifyIndependentRouteAttempts(policy.Independence(), generation.Authorization(), generation.Outcome(), verification.Authorization(), verification.Outcome())
	if err != nil {
		return "", err
	}
	return dryRunIdentity("local-inference-execution", plan.RootIdentity(), inventory.Identity(), policy.Identity(), catalog.Identity(), generation.Identity(), candidates.Identity(), verification.Identity(), verdicts.Identity(), independence.Identity(), "attempts:2", "fallbacks:0", "publication_attempts:0", "dynamic_validation_attempts:0"), nil
}

type localInferenceAdmission func(provider.Response) (string, error)

func executeSetupLocalInferenceRoute(ctx context.Context, catalog gateway.RouteDispatcherCatalog, request provider.Request, authorization gateway.RouteAttemptAuthorization, kind gateway.RouteOutputKind, admit localInferenceAdmission) (gateway.RouteExecutionRecord, error) {
	result, err := gateway.DispatchAuthorizedRouteFromCatalog(ctx, catalog, authorization, request)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	outcome, err := gateway.NewRouteAttemptOutcomeFromDispatch(authorization, result, 1)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	if result.Status() == gateway.RouteDispatchFailed {
		switch result.Failure() {
		case gateway.RouteFailureTransport, gateway.RouteFailureRateLimited, gateway.RouteFailureProviderServer, gateway.RouteFailureTimeout, gateway.RouteFailureConnection, gateway.RouteFailureCancelled:
			return gateway.RouteExecutionRecord{}, errLocalInferenceUnavailable
		default:
			return gateway.RouteExecutionRecord{}, ErrInvalidCheckerRuntime
		}
	}
	usage := result.Usage()
	if !usage.IsKnown() || usage.InputTokens() > setupLocalInferenceMaximumInputTokens || usage.OutputTokens() > authorization.MaxOutputTokens() {
		return gateway.RouteExecutionRecord{}, ErrInvalidCheckerRuntime
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
	output, err := gateway.NewSuccessfulRouteOutputReceipt(kind, dryRunIdentity("local-inference-context", request.Identity()), artifactIdentity, request, authorization, outcome)
	if err != nil {
		return gateway.RouteExecutionRecord{}, err
	}
	return gateway.NewRouteExecutionRecord(authorization, outcome, reconciliation, output)
}
func (c *LocalInferenceChecker) String() string   { return "setup local inference checker" }
func (c *LocalInferenceChecker) GoString() string { return "setup.LocalInferenceChecker{<redacted>}" }
func (c *LocalInferenceChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
