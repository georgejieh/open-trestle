package setup

import (
	"context"
	"fmt"
	"net"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// RemoteProviderAuthorizationChecker validates exact approved remote routing authority without resolving credentials or dispatching.
type RemoteProviderAuthorizationChecker struct {
	policyChecker                                                        *RuntimePolicyChecker
	policyConfigurationIdentity, approvalIdentity, configurationIdentity string
}

// NewRemoteProviderAuthorizationChecker binds an exact runtime-policy checker to the remote-provider requirement.
func NewRemoteProviderAuthorizationChecker(policyChecker *RuntimePolicyChecker) (*RemoteProviderAuthorizationChecker, error) {
	if !validRemotePolicyChecker(policyChecker) {
		return nil, ErrInvalidCheckerRuntime
	}
	configuration := checkerConfigIdentity(CheckRemoteProviderAuthorized, policyChecker.configurationIdentity+"\x00"+policyChecker.approval.Identity())
	return &RemoteProviderAuthorizationChecker{policyChecker, policyChecker.configurationIdentity, policyChecker.approval.Identity(), configuration}, nil
}
func validRemotePolicyChecker(checker *RuntimePolicyChecker) bool {
	return checker != nil && checker.immutableConfigurationValid()
}
func (c *RemoteProviderAuthorizationChecker) Key() CheckKey { return CheckRemoteProviderAuthorized }
func (c *RemoteProviderAuthorizationChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckRemoteProviderAuthorized)
}
func (c *RemoteProviderAuthorizationChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil && validRemotePolicyChecker(c.policyChecker) {
		approval := c.policyChecker.approval
		switch {
		case c.policyChecker.configurationIdentity != c.policyConfigurationIdentity || approval.Identity() != c.approvalIdentity:
			outcome = "checker_changed"
		case plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().Inference() != InferenceApprovedRemote || plan.Posture().Egress() != EgressAllowlisted:
			outcome = "profile_mismatch"
		case approval.rootIdentity != plan.RootIdentity() || approval.tenantID != plan.TenantID() || approval.repositoryID != plan.RepositoryID() || approval.approvedBy != plan.RecoveryOwner():
			outcome = "approval_mismatch"
		default:
			inventory, policy, loadedIdentity, loadState := c.policyChecker.load(ctx)
			if loadedIdentity != "" {
				configuration = checkerConfigIdentity(CheckRemoteProviderAuthorized, loadedIdentity+"\x00"+approval.Identity())
			}
			switch loadState {
			case runtimePolicyLoadUnavailable:
				state, outcome = CheckUnavailable, "configuration_unavailable"
			case runtimePolicyLoadBlocked:
				outcome = "configuration_invalid"
			case runtimePolicyLoadValid:
				if approval.validate(plan, inventory, policy) && runtimePolicyMatchesSetup(plan, inventory, policy) && hasAuthorizedRemoteProvider(inventory, policy) {
					state, outcome = CheckPassed, "authorized"
				} else {
					outcome = "authority_mismatch"
				}
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckRemoteProviderAuthorized), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckRemoteProviderAuthorized, state, evidence)
}
func hasAuthorizedRemoteProvider(inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) bool {
	if policy.Independence().Level() != gateway.RouteIndependenceDistinctProvider || policy.Publication().MinimumIndependence() != gateway.RouteIndependenceDistinctProvider {
		return false
	}
	connections := map[string]runtimeconfig.ProviderConnection{}
	for _, connection := range policy.Connections() {
		connections[connection.AdapterID()] = connection
	}
	type authority struct{ providerID, connectionID, endpointOrigin, credentialIdentity string }
	eligible := []authority{}
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		candidate := record.RouteCandidateDeclaration()
		reference := candidate.RouteCapabilityDeclaration().RouteReference()
		connection, found := connections[reference.AdapterID()]
		if !found {
			return false
		}
		if reference.Zone() != provider.ProviderZonePrivateRemote || !routeReadyForPolicy(observed, policy) {
			continue
		}
		endpoint, err := provider.ParseServiceEndpoint(connection.Endpoint())
		if err != nil {
			return false
		}
		port := endpoint.Port()
		if port == "" {
			if endpoint.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		origin := endpoint.Scheme + "://" + net.JoinHostPort(endpoint.Hostname(), port)
		eligible = append(eligible, authority{reference.ProviderID(), reference.ConnectionID(), origin, connection.CredentialIdentity()})
	}
	for i := 0; i < len(eligible); i++ {
		for j := i + 1; j < len(eligible); j++ {
			if eligible[i].providerID != eligible[j].providerID && eligible[i].connectionID != eligible[j].connectionID && eligible[i].endpointOrigin != eligible[j].endpointOrigin && eligible[i].credentialIdentity != eligible[j].credentialIdentity {
				return true
			}
		}
	}
	return false
}
func (c *RemoteProviderAuthorizationChecker) String() string {
	return "setup remote provider authorization checker"
}
func (c *RemoteProviderAuthorizationChecker) GoString() string {
	return "setup.RemoteProviderAuthorizationChecker{<redacted>}"
}
func (c *RemoteProviderAuthorizationChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
