package setup

import (
	"context"
	"fmt"
	"time"
)

const setupReplicaReconciliationTimeout = 60 * time.Second

type replicaReconciliationProbeState uint8

const (
	replicaReconciliationProbeVerified replicaReconciliationProbeState = iota + 1
	replicaReconciliationProbeUnavailable
	replicaReconciliationProbeInvalid
)

// ReplicaReconciliationProbeResult is one closed content-free replica-reconciliation outcome.
type ReplicaReconciliationProbeResult struct {
	state                                  replicaReconciliationProbeState
	authorityIdentity, observationIdentity string
}

// NewVerifiedReplicaReconciliationProbeResult records exact authority and observation identities.
func NewVerifiedReplicaReconciliationProbeResult(authority, observation string) ReplicaReconciliationProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(observation) {
		return ReplicaReconciliationProbeResult{}
	}
	return ReplicaReconciliationProbeResult{replicaReconciliationProbeVerified, authority, observation}
}

// NewUnavailableReplicaReconciliationProbeResult records a transient inspection failure.
func NewUnavailableReplicaReconciliationProbeResult() ReplicaReconciliationProbeResult {
	return ReplicaReconciliationProbeResult{state: replicaReconciliationProbeUnavailable}
}

// NewInvalidReplicaReconciliationProbeResult records malformed or contradictory reconciliation behavior.
func NewInvalidReplicaReconciliationProbeResult() ReplicaReconciliationProbeResult {
	return ReplicaReconciliationProbeResult{state: replicaReconciliationProbeInvalid}
}
func (r ReplicaReconciliationProbeResult) validate() bool {
	switch r.state {
	case replicaReconciliationProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.observationIdentity)
	case replicaReconciliationProbeUnavailable, replicaReconciliationProbeInvalid:
		return r.authorityIdentity == "" && r.observationIdentity == ""
	}
	return false
}
func (r ReplicaReconciliationProbeResult) String() string {
	return "replica reconciliation probe result"
}
func (r ReplicaReconciliationProbeResult) GoString() string {
	return "setup.ReplicaReconciliationProbeResult{<redacted>}"
}
func (r ReplicaReconciliationProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// ReplicaReconciliationProbe performs one bounded replica-reconciliation conformance cycle.
type ReplicaReconciliationProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) ReplicaReconciliationProbeResult
}

// ReplicaReconciliationChecker binds approved reconciliation authority, setup scope, and actor.
type ReplicaReconciliationChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy                            string
	expectedAuthority, probeAuthority, probeIdentity, dependencyReceipt, configurationIdentity string
	probe                                                                                      ReplicaReconciliationProbe
}

// NewReplicaReconciliationChecker constructs a checker without reading a database credential.
func NewReplicaReconciliationChecker(plan Plan, expectedAuthority, approvedBy string, probe ReplicaReconciliationProbe) (*ReplicaReconciliationChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	dependency := passedRequirementReceiptIdentity(plan, CheckPostgresStorageValidated)
	configuration := checkerConfigIdentity(CheckReplicaReconciliationValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity+"\x00"+dependency)
	return &ReplicaReconciliationChecker{rootIdentity: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), approvedBy: approvedBy, expectedAuthority: expectedAuthority, probeAuthority: probeAuthority, probeIdentity: probeIdentity, dependencyReceipt: dependency, configurationIdentity: configuration, probe: probe}, nil
}
func (c *ReplicaReconciliationChecker) Key() CheckKey {
	return CheckReplicaReconciliationValidated
}
func (c *ReplicaReconciliationChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckReplicaReconciliationValidated)
}
func (c *ReplicaReconciliationChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		dependency := passedRequirementReceiptIdentity(plan, CheckPostgresStorageValidated)
		switch {
		case plan.Profile() != ProfileKubernetesHA || plan.Posture().MetadataBackend() != MetadataPostgres || plan.Posture().NotificationBackend() != NotificationPostgres || plan.Posture().PublicationEnabled():
			outcome = "profile_mismatch"
		case plan.RootIdentity() != c.rootIdentity || plan.TenantID() != c.tenantID || plan.RepositoryID() != c.repositoryID || plan.RecoveryOwner() != c.recoveryOwner:
			outcome = "scope_mismatch"
		case c.approvedBy != c.recoveryOwner:
			outcome = "approval_mismatch"
		case c.dependencyReceipt == "" || dependency != c.dependencyReceipt:
			outcome = "postgres_dependency_mismatch"
		case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority:
			outcome = "probe_changed"
		case c.probeAuthority != c.expectedAuthority:
			outcome = "authority_mismatch"
		default:
			bounded, cancel := context.WithTimeout(ctx, setupReplicaReconciliationTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == replicaReconciliationProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == replicaReconciliationProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.observationIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckReplicaReconciliationValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckReplicaReconciliationValidated, state, evidence)
}
func (c *ReplicaReconciliationChecker) String() string {
	return "setup replica reconciliation checker"
}
func (c *ReplicaReconciliationChecker) GoString() string {
	return "setup.ReplicaReconciliationChecker{<redacted>}"
}
func (c *ReplicaReconciliationChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
