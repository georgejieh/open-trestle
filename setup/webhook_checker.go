package setup

import (
	"context"
	"fmt"
	"time"
)

const setupWebhookTimeout = 30 * time.Second

type webhookProbeState uint8

const (
	webhookProbeVerified webhookProbeState = iota + 1
	webhookProbeUnavailable
	webhookProbeInvalid
)

// WebhookProbeResult is one closed content-free webhook-conformance outcome.
type WebhookProbeResult struct {
	state                                  webhookProbeState
	authorityIdentity, observationIdentity string
}

// NewVerifiedWebhookProbeResult records exact authority and observation identities.
func NewVerifiedWebhookProbeResult(authority, observation string) WebhookProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(observation) {
		return WebhookProbeResult{}
	}
	return WebhookProbeResult{webhookProbeVerified, authority, observation}
}

// NewUnavailableWebhookProbeResult records a transient inspection failure.
func NewUnavailableWebhookProbeResult() WebhookProbeResult {
	return WebhookProbeResult{state: webhookProbeUnavailable}
}

// NewInvalidWebhookProbeResult records malformed or contradictory webhook behavior.
func NewInvalidWebhookProbeResult() WebhookProbeResult {
	return WebhookProbeResult{state: webhookProbeInvalid}
}
func (r WebhookProbeResult) validate() bool {
	switch r.state {
	case webhookProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.observationIdentity)
	case webhookProbeUnavailable, webhookProbeInvalid:
		return r.authorityIdentity == "" && r.observationIdentity == ""
	}
	return false
}
func (r WebhookProbeResult) String() string {
	return "webhook probe result"
}
func (r WebhookProbeResult) GoString() string {
	return "setup.WebhookProbeResult{<redacted>}"
}
func (r WebhookProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// WebhookProbe performs one bounded webhook conformance cycle.
type WebhookProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) WebhookProbeResult
}

// WebhookChecker binds approved webhook authority, setup scope, actor, and permission evidence to a setup scope.
type WebhookChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy                            string
	expectedAuthority, probeAuthority, probeIdentity, dependencyReceipt, configurationIdentity string
	probe                                                                                      WebhookProbe
}

// NewWebhookChecker constructs a checker without reading credentials or contacting a forge.
func NewWebhookChecker(plan Plan, expectedAuthority, approvedBy string, probe WebhookProbe) (*WebhookChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	dependency := passedRequirementReceiptIdentity(plan, CheckIntegrationPermissionsValidated)
	configuration := checkerConfigIdentity(CheckWebhookValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity+"\x00"+dependency)
	return &WebhookChecker{rootIdentity: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), approvedBy: approvedBy, expectedAuthority: expectedAuthority, probeAuthority: probeAuthority, probeIdentity: probeIdentity, dependencyReceipt: dependency, configurationIdentity: configuration, probe: probe}, nil
}
func (c *WebhookChecker) Key() CheckKey { return CheckWebhookValidated }
func (c *WebhookChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckWebhookValidated)
}
func (c *WebhookChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		dependency := passedRequirementReceiptIdentity(plan, CheckIntegrationPermissionsValidated)
		switch {
		case plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().Integration() != IntegrationLeastPrivilegeSCM || plan.Posture().PublicationEnabled():
			outcome = "profile_mismatch"
		case plan.RootIdentity() != c.rootIdentity || plan.TenantID() != c.tenantID || plan.RepositoryID() != c.repositoryID || plan.RecoveryOwner() != c.recoveryOwner:
			outcome = "scope_mismatch"
		case c.approvedBy != c.recoveryOwner:
			outcome = "approval_mismatch"
		case c.dependencyReceipt == "" || dependency != c.dependencyReceipt:
			outcome = "permission_dependency_mismatch"
		case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority:
			outcome = "probe_changed"
		case c.probeAuthority != c.expectedAuthority:
			outcome = "authority_mismatch"
		default:
			bounded, cancel := context.WithTimeout(ctx, setupWebhookTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == webhookProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == webhookProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.observationIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckWebhookValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckWebhookValidated, state, evidence)
}
func (c *WebhookChecker) String() string { return "setup webhook checker" }
func (c *WebhookChecker) GoString() string {
	return "setup.WebhookChecker{<redacted>}"
}
func (c *WebhookChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
