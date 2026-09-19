package setup

import (
	"context"
	"fmt"
	"time"
)

const setupSecretBackendTimeout = 60 * time.Second

type secretBackendProbeState uint8

const (
	secretBackendProbeVerified secretBackendProbeState = iota + 1
	secretBackendProbeUnavailable
	secretBackendProbeInvalid
)

// SecretBackendProbeResult is one closed content-free tenant-key round-trip outcome.
type SecretBackendProbeResult struct {
	state             secretBackendProbeState
	authorityIdentity string
}

// NewVerifiedSecretBackendProbeResult records one exact KMS configuration identity.
func NewVerifiedSecretBackendProbeResult(identity string) SecretBackendProbeResult {
	if !nonzeroSetupDigest(identity) {
		return SecretBackendProbeResult{}
	}
	return SecretBackendProbeResult{secretBackendProbeVerified, identity}
}

// NewUnavailableSecretBackendProbeResult records a transient secret-backend failure.
func NewUnavailableSecretBackendProbeResult() SecretBackendProbeResult {
	return SecretBackendProbeResult{state: secretBackendProbeUnavailable}
}

// NewInvalidSecretBackendProbeResult records invalid or cross-wired secret-backend behavior.
func NewInvalidSecretBackendProbeResult() SecretBackendProbeResult {
	return SecretBackendProbeResult{state: secretBackendProbeInvalid}
}
func (r SecretBackendProbeResult) validate() bool {
	switch r.state {
	case secretBackendProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity)
	case secretBackendProbeUnavailable, secretBackendProbeInvalid:
		return r.authorityIdentity == ""
	}
	return false
}
func (r SecretBackendProbeResult) String() string { return "secret backend probe result" }
func (r SecretBackendProbeResult) GoString() string {
	return "setup.SecretBackendProbeResult{<redacted>}"
}
func (r SecretBackendProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// SecretBackendProbe performs one tenant-bound generate and unwrap operation.
type SecretBackendProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) SecretBackendProbeResult
}

// SecretBackendChecker binds one approved KMS authority to a setup scope and probe.
type SecretBackendChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy, expectedAuthority, probeAuthority, probeIdentity, configurationIdentity string
	probe                                                                                                                                    SecretBackendProbe
}

// NewSecretBackendChecker constructs a checker without accessing credentials or KMS.
func NewSecretBackendChecker(plan Plan, expectedAuthority, approvedBy string, probe SecretBackendProbe) (*SecretBackendChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	configuration := checkerConfigIdentity(CheckSecretBackendValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity)
	return &SecretBackendChecker{plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), approvedBy, expectedAuthority, probeAuthority, probeIdentity, configuration, probe}, nil
}
func (c *SecretBackendChecker) Key() CheckKey { return CheckSecretBackendValidated }
func (c *SecretBackendChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckSecretBackendValidated)
}
func (c *SecretBackendChecker) Check(ctx context.Context, plan Plan) CheckResult {
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
			bounded, cancel := context.WithTimeout(ctx, setupSecretBackendTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == secretBackendProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == secretBackendProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid"
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckSecretBackendValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckSecretBackendValidated, state, evidence)
}
func (c *SecretBackendChecker) String() string   { return "setup secret backend checker" }
func (c *SecretBackendChecker) GoString() string { return "setup.SecretBackendChecker{<redacted>}" }
func (c *SecretBackendChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
