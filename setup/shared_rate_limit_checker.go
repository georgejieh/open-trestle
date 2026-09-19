package setup

import (
	"context"
	"fmt"
	"time"
)

const setupSharedRateLimitTimeout = 60 * time.Second

type sharedRateLimitProbeState uint8

const (
	sharedRateLimitProbeVerified sharedRateLimitProbeState = iota + 1
	sharedRateLimitProbeUnavailable
	sharedRateLimitProbeInvalid
)

// SharedRateLimitProbeResult is one closed content-free shared-rate-limit conformance outcome.
type SharedRateLimitProbeResult struct {
	state                                  sharedRateLimitProbeState
	authorityIdentity, observationIdentity string
}

// NewVerifiedSharedRateLimitProbeResult records exact authority and observation identities.
func NewVerifiedSharedRateLimitProbeResult(authority, observation string) SharedRateLimitProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(observation) {
		return SharedRateLimitProbeResult{}
	}
	return SharedRateLimitProbeResult{sharedRateLimitProbeVerified, authority, observation}
}

// NewUnavailableSharedRateLimitProbeResult records a transient inspection failure.
func NewUnavailableSharedRateLimitProbeResult() SharedRateLimitProbeResult {
	return SharedRateLimitProbeResult{state: sharedRateLimitProbeUnavailable}
}

// NewInvalidSharedRateLimitProbeResult records malformed or contradictory shared-limiter behavior.
func NewInvalidSharedRateLimitProbeResult() SharedRateLimitProbeResult {
	return SharedRateLimitProbeResult{state: sharedRateLimitProbeInvalid}
}
func (r SharedRateLimitProbeResult) validate() bool {
	switch r.state {
	case sharedRateLimitProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.observationIdentity)
	case sharedRateLimitProbeUnavailable, sharedRateLimitProbeInvalid:
		return r.authorityIdentity == "" && r.observationIdentity == ""
	}
	return false
}
func (r SharedRateLimitProbeResult) String() string {
	return "shared rate-limit probe result"
}
func (r SharedRateLimitProbeResult) GoString() string {
	return "setup.SharedRateLimitProbeResult{<redacted>}"
}
func (r SharedRateLimitProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// SharedRateLimitProbe performs one bounded shared-rate-limit conformance cycle.
type SharedRateLimitProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) SharedRateLimitProbeResult
}

// SharedRateLimitChecker binds approved shared rate-limit authority, setup scope, actor, and database evidence.
type SharedRateLimitChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy                            string
	expectedAuthority, probeAuthority, probeIdentity, dependencyReceipt, configurationIdentity string
	probe                                                                                      SharedRateLimitProbe
}

// NewSharedRateLimitChecker constructs a checker without reading the database credential or opening a connection.
func NewSharedRateLimitChecker(plan Plan, expectedAuthority, approvedBy string, probe SharedRateLimitProbe) (*SharedRateLimitChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	dependency := passedRequirementReceiptIdentity(plan, CheckPostgresStorageValidated)
	configuration := checkerConfigIdentity(CheckSharedRateLimitValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity+"\x00"+dependency)
	return &SharedRateLimitChecker{rootIdentity: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), approvedBy: approvedBy, expectedAuthority: expectedAuthority, probeAuthority: probeAuthority, probeIdentity: probeIdentity, dependencyReceipt: dependency, configurationIdentity: configuration, probe: probe}, nil
}
func (c *SharedRateLimitChecker) Key() CheckKey { return CheckSharedRateLimitValidated }
func (c *SharedRateLimitChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckSharedRateLimitValidated)
}
func (c *SharedRateLimitChecker) Check(ctx context.Context, plan Plan) CheckResult {
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
			bounded, cancel := context.WithTimeout(ctx, setupSharedRateLimitTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == sharedRateLimitProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == sharedRateLimitProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.observationIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckSharedRateLimitValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckSharedRateLimitValidated, state, evidence)
}
func (c *SharedRateLimitChecker) String() string { return "setup shared rate-limit checker" }
func (c *SharedRateLimitChecker) GoString() string {
	return "setup.SharedRateLimitChecker{<redacted>}"
}
func (c *SharedRateLimitChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
