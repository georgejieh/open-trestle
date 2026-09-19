package setup

import (
	"context"
	"fmt"
	"time"
)

const setupEnvelopeStorageTimeout = 90 * time.Second

type envelopeStorageProbeState uint8

const (
	envelopeStorageProbeVerified envelopeStorageProbeState = iota + 1
	envelopeStorageProbeUnavailable
	envelopeStorageProbeInvalid
)

// EnvelopeStorageProbeResult is one closed content-free encrypted object round-trip outcome.
type EnvelopeStorageProbeResult struct {
	state                                  envelopeStorageProbeState
	authorityIdentity, conformanceIdentity string
}

// NewVerifiedEnvelopeStorageProbeResult records exact authority and terminal conformance identities.
func NewVerifiedEnvelopeStorageProbeResult(authority, conformance string) EnvelopeStorageProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(conformance) {
		return EnvelopeStorageProbeResult{}
	}
	return EnvelopeStorageProbeResult{envelopeStorageProbeVerified, authority, conformance}
}

// NewUnavailableEnvelopeStorageProbeResult records a transient storage or key-service failure.
func NewUnavailableEnvelopeStorageProbeResult() EnvelopeStorageProbeResult {
	return EnvelopeStorageProbeResult{state: envelopeStorageProbeUnavailable}
}

// NewInvalidEnvelopeStorageProbeResult records invalid or cross-wired envelope behavior.
func NewInvalidEnvelopeStorageProbeResult() EnvelopeStorageProbeResult {
	return EnvelopeStorageProbeResult{state: envelopeStorageProbeInvalid}
}
func (r EnvelopeStorageProbeResult) validate() bool {
	switch r.state {
	case envelopeStorageProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.conformanceIdentity)
	case envelopeStorageProbeUnavailable, envelopeStorageProbeInvalid:
		return r.authorityIdentity == "" && r.conformanceIdentity == ""
	}
	return false
}
func (r EnvelopeStorageProbeResult) String() string { return "envelope storage probe result" }
func (r EnvelopeStorageProbeResult) GoString() string {
	return "setup.EnvelopeStorageProbeResult{<redacted>}"
}
func (r EnvelopeStorageProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// EnvelopeStorageProbe performs one fixed encrypted object create, read, exact delete, and absence check.
type EnvelopeStorageProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) EnvelopeStorageProbeResult
}

// EnvelopeStorageChecker binds one approved envelope authority to a setup scope and probe.
type EnvelopeStorageChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy, expectedAuthority, probeAuthority, probeIdentity, configurationIdentity string
	probe                                                                                                                                    EnvelopeStorageProbe
}

// NewEnvelopeStorageChecker constructs a checker without reading credentials or contacting storage.
func NewEnvelopeStorageChecker(plan Plan, expectedAuthority, approvedBy string, probe EnvelopeStorageProbe) (*EnvelopeStorageChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	configuration := checkerConfigIdentity(CheckEnvelopeStorageValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity)
	return &EnvelopeStorageChecker{plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), approvedBy, expectedAuthority, probeAuthority, probeIdentity, configuration, probe}, nil
}
func (c *EnvelopeStorageChecker) Key() CheckKey { return CheckEnvelopeStorageValidated }
func (c *EnvelopeStorageChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckEnvelopeStorageValidated)
}
func (c *EnvelopeStorageChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		switch {
		case plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().ArtifactBackend() != ArtifactS3 || plan.Posture().Protection() != ProtectionEnvelopeEncrypted:
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
			bounded, cancel := context.WithTimeout(ctx, setupEnvelopeStorageTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == envelopeStorageProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == envelopeStorageProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.conformanceIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckEnvelopeStorageValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckEnvelopeStorageValidated, state, evidence)
}
func (c *EnvelopeStorageChecker) String() string   { return "setup envelope storage checker" }
func (c *EnvelopeStorageChecker) GoString() string { return "setup.EnvelopeStorageChecker{<redacted>}" }
func (c *EnvelopeStorageChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
