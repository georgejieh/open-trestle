package setup

import (
	"context"
	"fmt"
	"time"
)

const setupSignedBundleTimeout = 90 * time.Second

type signedBundleProbeState uint8

const (
	signedBundleProbeVerified signedBundleProbeState = iota + 1
	signedBundleProbeUnavailable
	signedBundleProbeInvalid
)

// SignedBundleProbeResult is one closed content-free bundle validation outcome.
type SignedBundleProbeResult struct {
	state                                  signedBundleProbeState
	authorityIdentity, observationIdentity string
}

// NewVerifiedSignedBundleProbeResult records exact authority and observation identities.
func NewVerifiedSignedBundleProbeResult(authority, observation string) SignedBundleProbeResult {
	if !nonzeroSetupDigest(authority) || !nonzeroSetupDigest(observation) {
		return SignedBundleProbeResult{}
	}
	return SignedBundleProbeResult{signedBundleProbeVerified, authority, observation}
}

// NewUnavailableSignedBundleProbeResult records a transient local file failure.
func NewUnavailableSignedBundleProbeResult() SignedBundleProbeResult {
	return SignedBundleProbeResult{state: signedBundleProbeUnavailable}
}

// NewInvalidSignedBundleProbeResult records malformed or contradictory bundle evidence.
func NewInvalidSignedBundleProbeResult() SignedBundleProbeResult {
	return SignedBundleProbeResult{state: signedBundleProbeInvalid}
}
func (r SignedBundleProbeResult) validate() bool {
	switch r.state {
	case signedBundleProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity) && nonzeroSetupDigest(r.observationIdentity)
	case signedBundleProbeUnavailable, signedBundleProbeInvalid:
		return r.authorityIdentity == "" && r.observationIdentity == ""
	}
	return false
}
func (r SignedBundleProbeResult) String() string { return "signed offline bundle probe result" }
func (r SignedBundleProbeResult) GoString() string {
	return "setup.SignedBundleProbeResult{<redacted>}"
}
func (r SignedBundleProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// SignedBundleProbe performs one bounded local opaque-bundle verification.
type SignedBundleProbe interface {
	ConfigurationIdentity() string
	AuthorityIdentity() string
	Probe(context.Context) SignedBundleProbeResult
}

// SignedBundleChecker binds approved bundle authority to one air-gapped setup plan.
type SignedBundleChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy         string
	expectedAuthority, probeAuthority, probeIdentity, configurationIdentity string
	probe                                                                   SignedBundleProbe
}

// NewSignedBundleChecker constructs a checker without opening the bundle file.
func NewSignedBundleChecker(plan Plan, expectedAuthority, approvedBy string, probe SignedBundleProbe) (*SignedBundleChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity, probeAuthority := probe.ConfigurationIdentity(), probe.AuthorityIdentity()
	if !nonzeroSetupDigest(probeIdentity) || !nonzeroSetupDigest(probeAuthority) {
		return nil, ErrInvalidCheckerRuntime
	}
	configuration := checkerConfigIdentity(CheckSignedBundleValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeAuthority+"\x00"+probeIdentity)
	return &SignedBundleChecker{rootIdentity: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), approvedBy: approvedBy, expectedAuthority: expectedAuthority, probeAuthority: probeAuthority, probeIdentity: probeIdentity, configurationIdentity: configuration, probe: probe}, nil
}
func (c *SignedBundleChecker) Key() CheckKey { return CheckSignedBundleValidated }
func (c *SignedBundleChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckSignedBundleValidated)
}
func (c *SignedBundleChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configuration := ""
	if c != nil {
		configuration = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		posture := plan.Posture()
		switch {
		case plan.Profile() != ProfileAirGapped || posture.MetadataBackend() != MetadataLocal || posture.ArtifactBackend() != ArtifactLocal || posture.Protection() != ProtectionProcessPrivate || posture.NotificationBackend() != NotificationProcessLocal || posture.Inference() != InferenceLocalOnly || posture.Egress() != EgressDenied || posture.Integration() != IntegrationOfflineBundle || posture.PublicationEnabled() || posture.DynamicValidationEnabled():
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
			bounded, cancel := context.WithTimeout(ctx, setupSignedBundleTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || c.probe.AuthorityIdentity() != c.probeAuthority || !result.validate():
				outcome = "probe_invalid"
			case result.state == signedBundleProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == signedBundleProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.probeAuthority || result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid:"+result.observationIdentity
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckSignedBundleValidated), configuration, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckSignedBundleValidated, state, evidence)
}
func (c *SignedBundleChecker) String() string { return "setup signed offline bundle checker" }
func (c *SignedBundleChecker) GoString() string {
	return "setup.SignedBundleChecker{<redacted>}"
}
func (c *SignedBundleChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
