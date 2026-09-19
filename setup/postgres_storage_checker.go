package setup

import (
	"context"
	"fmt"
	"time"
)

const setupPostgresStorageTimeout = 30 * time.Second

type postgresStorageProbeState uint8

const (
	postgresStorageProbeVerified postgresStorageProbeState = iota + 1
	postgresStorageProbeUnavailable
	postgresStorageProbeInvalid
)

// PostgresStorageProbeResult is one closed content-free database verification outcome.
type PostgresStorageProbeResult struct {
	state             postgresStorageProbeState
	authorityIdentity string
}

// NewVerifiedPostgresStorageProbeResult records one exact database authority.
func NewVerifiedPostgresStorageProbeResult(authorityIdentity string) PostgresStorageProbeResult {
	if !nonzeroSetupDigest(authorityIdentity) {
		return PostgresStorageProbeResult{}
	}
	return PostgresStorageProbeResult{postgresStorageProbeVerified, authorityIdentity}
}

// NewUnavailablePostgresStorageProbeResult records a transient probe failure.
func NewUnavailablePostgresStorageProbeResult() PostgresStorageProbeResult {
	return PostgresStorageProbeResult{state: postgresStorageProbeUnavailable}
}

// NewInvalidPostgresStorageProbeResult records malformed or incompatible database state.
func NewInvalidPostgresStorageProbeResult() PostgresStorageProbeResult {
	return PostgresStorageProbeResult{state: postgresStorageProbeInvalid}
}
func (r PostgresStorageProbeResult) validate() bool {
	switch r.state {
	case postgresStorageProbeVerified:
		return nonzeroSetupDigest(r.authorityIdentity)
	case postgresStorageProbeUnavailable, postgresStorageProbeInvalid:
		return r.authorityIdentity == ""
	}
	return false
}

func (r PostgresStorageProbeResult) String() string { return "PostgreSQL storage probe result" }
func (r PostgresStorageProbeResult) GoString() string {
	return "setup.PostgresStorageProbeResult{<redacted>}"
}
func (r PostgresStorageProbeResult) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}

// PostgresStorageProbe verifies one request-time database without exposing connection material.
type PostgresStorageProbe interface {
	ConfigurationIdentity() string
	Probe(context.Context) PostgresStorageProbeResult
}

// PostgresStorageChecker binds a database authority approval to one setup scope and probe implementation.
type PostgresStorageChecker struct {
	rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy, expectedAuthority, probeIdentity, configurationIdentity string
	probe                                                                                                                    PostgresStorageProbe
}

// NewPostgresStorageChecker creates a checker without accessing credentials or a database.
func NewPostgresStorageChecker(plan Plan, expectedAuthority, approvedBy string, probe PostgresStorageProbe) (*PostgresStorageChecker, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(expectedAuthority) || !validSetupLabel(approvedBy) || nilSetupInterface(probe) {
		return nil, ErrInvalidCheckerRuntime
	}
	probeIdentity := probe.ConfigurationIdentity()
	if !nonzeroSetupDigest(probeIdentity) {
		return nil, ErrInvalidCheckerRuntime
	}
	configurationIdentity := checkerConfigIdentity(CheckPostgresStorageValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+approvedBy+"\x00"+expectedAuthority+"\x00"+probeIdentity)
	return &PostgresStorageChecker{plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), approvedBy, expectedAuthority, probeIdentity, configurationIdentity, probe}, nil
}
func (c *PostgresStorageChecker) Key() CheckKey { return CheckPostgresStorageValidated }
func (c *PostgresStorageChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckPostgresStorageValidated)
}
func (c *PostgresStorageChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		switch {
		case plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().MetadataBackend() != MetadataPostgres:
			outcome = "profile_mismatch"
		case plan.RootIdentity() != c.rootIdentity || plan.TenantID() != c.tenantID || plan.RepositoryID() != c.repositoryID || plan.RecoveryOwner() != c.recoveryOwner:
			outcome = "scope_mismatch"
		case c.approvedBy != c.recoveryOwner:
			outcome = "approval_mismatch"
		case c.probe.ConfigurationIdentity() != c.probeIdentity:
			outcome = "probe_changed"
		default:
			bounded, cancel := context.WithTimeout(ctx, setupPostgresStorageTimeout)
			result := c.probe.Probe(bounded)
			deadlineErr := bounded.Err()
			cancel()
			switch {
			case deadlineErr != nil:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case c.probe.ConfigurationIdentity() != c.probeIdentity || !result.validate():
				outcome = "probe_invalid"
			case result.state == postgresStorageProbeUnavailable:
				state, outcome = CheckUnavailable, "probe_unavailable"
			case result.state == postgresStorageProbeInvalid:
				outcome = "probe_invalid"
			case result.authorityIdentity != c.expectedAuthority:
				outcome = "authority_mismatch"
			default:
				state, outcome = CheckPassed, "valid"
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckPostgresStorageValidated), configurationIdentity, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckPostgresStorageValidated, state, evidence)
}
func (c *PostgresStorageChecker) String() string   { return "setup PostgreSQL storage checker" }
func (c *PostgresStorageChecker) GoString() string { return "setup.PostgresStorageChecker{<redacted>}" }
func (c *PostgresStorageChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
