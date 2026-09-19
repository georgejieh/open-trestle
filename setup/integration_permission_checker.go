package setup

import (
	"context"
	"fmt"
	"time"
)

const setupIntegrationPermissionTimeout = 60 * time.Second

type integrationPermissionProbeState uint8

const (
	integrationPermissionProbeVerified integrationPermissionProbeState = iota + 1
	integrationPermissionProbeUnavailable
	integrationPermissionProbeInvalid
)

// IntegrationPermissionProbeResult is one closed content-free permission-inspection outcome.
type IntegrationPermissionProbeResult struct {
	state                                  integrationPermissionProbeState
	authorityIdentity, observationIdentity string
}

// NewVerifiedIntegrationPermissionProbeResult records exact authority and observation identities.
func NewVerifiedIntegrationPermissionProbeResult(authority, observation string) IntegrationPermissionProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(observation) {
		return IntegrationPermissionProbeResult{}
	}
	return IntegrationPermissionProbeResult{integrationPermissionProbeVerified, authority, observation}
}

// NewUnavailableIntegrationPermissionProbeResult records a transient inspection failure.
func NewUnavailableIntegrationPermissionProbeResult() IntegrationPermissionProbeResult {
	return IntegrationPermissionProbeResult{state: integrationPermissionProbeUnavailable}
}

// NewInvalidIntegrationPermissionProbeResult records denied, excessive, or crossed permission state.
func NewInvalidIntegrationPermissionProbeResult() IntegrationPermissionProbeResult {
	return IntegrationPermissionProbeResult{state: integrationPermissionProbeInvalid}
}
func (r IntegrationPermissionProbeResult) validate() bool {
	switch r.state {
	case integrationPermissionProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.observationIdentity)
	case integrationPermissionProbeUnavailable, integrationPermissionProbeInvalid:
		return r.authorityIdentity == "" && r.observationIdentity == ""
	}
	return false
}
func (r IntegrationPermissionProbeResult) String() string {
	return "integration permission probe result"
}
func (r IntegrationPermissionProbeResult) GoString() string {
	return "setup.IntegrationPermissionProbeResult{<redacted>}"
}
func (r IntegrationPermissionProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// IntegrationPermissionProbe performs one bounded permission observation.
type IntegrationPermissionProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) IntegrationPermissionProbeResult
}

// IntegrationPermissionChecker binds one approved integration authority to a setup scope.
type IntegrationPermissionChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy, expectedAuthority, probeAuthority, probeIdentity, configurationIdentity string
	probe                                                                                                                                    IntegrationPermissionProbe
}

// NewIntegrationPermissionChecker constructs a checker without reading credentials or contacting a forge.
func NewIntegrationPermissionChecker(plan Plan, expectedAuthority, approvedBy string, probe IntegrationPermissionProbe) (*IntegrationPermissionChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	configuration := checkerConfigIdentity(CheckIntegrationPermissionsValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity)
	return &IntegrationPermissionChecker{plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), approvedBy, expectedAuthority, probeAuthority, probeIdentity, configuration, probe}, nil
}
func (c *IntegrationPermissionChecker) Key() CheckKey { return CheckIntegrationPermissionsValidated }
func (c *IntegrationPermissionChecker) CheckerIdentity() string {
	return CurrentIntegrationPermissionCheckerIdentity()
}
func (c *IntegrationPermissionChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		switch {
		case plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().Integration() != IntegrationLeastPrivilegeSCM || plan.Posture().PublicationEnabled():
			outcome = "profile_mismatch"
		case plan.RootIdentity() != c.rootIdentity || plan.TenantID() != c.tenantID || plan.RepositoryID() != c.repositoryID || plan.RecoveryOwner() != c.recoveryOwner:
			outcome = "scope_mismatch"
		case c.approvedBy != c.recoveryOwner:
			outcome = "approval_mismatch"
		case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority:
			outcome = "probe_changed"
		case c.probeAuthority != c.expectedAuthority:
			outcome = "authority_mismatch"
		default:
			bounded, cancel := context.WithTimeout(ctx, setupIntegrationPermissionTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == integrationPermissionProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == integrationPermissionProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.observationIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), CurrentIntegrationPermissionCheckerIdentity(), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckIntegrationPermissionsValidated, state, evidence)
}
func (c *IntegrationPermissionChecker) String() string { return "setup integration permission checker" }
func (c *IntegrationPermissionChecker) GoString() string {
	return "setup.IntegrationPermissionChecker{<redacted>}"
}
func (c *IntegrationPermissionChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
