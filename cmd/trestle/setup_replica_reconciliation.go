package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupReplicaReconciliationConfiguration struct{ databaseAuthorityIdentity, setupRootIdentity string }
type setupReplicaReconciliationExecutor func(context.Context, setupReplicaReconciliationConfiguration, string) (string, error)
type setupReplicaReconciliationProbe struct {
	environment                                                        func(string) string
	configuration                                                      setupReplicaReconciliationConfiguration
	planRoot, tenantID, repositoryID, recoveryOwner, authorityIdentity string
	execute                                                            setupReplicaReconciliationExecutor
}

func deriveSetupReplicaReconciliationAuthority(configuration setupReplicaReconciliationConfiguration) (string, error) {
	return postgresstore.ReplicaReconciliationConformanceAuthorityIdentity(configuration.databaseAuthorityIdentity, setupPostgresURLCredentialIdentity(), configuration.setupRootIdentity)
}
func digestSetupReplicaReconciliation(value string) string {
	sum := sha256.Sum256([]byte("open-trestle/setup-replica-reconciliation/v1\x00" + value))
	return hex.EncodeToString(sum[:])
}
func newSetupReplicaReconciliationProbe(environment func(string) string, plan setupcore.Plan, databaseAuthorityIdentity string, execute setupReplicaReconciliationExecutor) (*setupReplicaReconciliationProbe, string, error) {
	if environment == nil || execute == nil || plan.Validate() != nil {
		return nil, "", errors.New("invalid replica reconciliation setup probe")
	}
	configuration := setupReplicaReconciliationConfiguration{databaseAuthorityIdentity, plan.RootIdentity()}
	authority, err := deriveSetupReplicaReconciliationAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	probe := &setupReplicaReconciliationProbe{environment: environment, configuration: configuration, planRoot: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), authorityIdentity: authority, execute: execute}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", errors.New("invalid replica reconciliation setup probe")
	}
	return probe, authority, nil
}
func (p *setupReplicaReconciliationProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, err := deriveSetupReplicaReconciliationAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func (p *setupReplicaReconciliationProbe) ConfigurationIdentity() string {
	if p == nil || p.planRoot == "" || p.tenantID == "" || p.repositoryID == "" || p.recoveryOwner == "" {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" || p.configuration.setupRootIdentity != p.planRoot {
		return ""
	}
	return digestSetupReplicaReconciliation("probe:" + authority + "\x00" + p.planRoot + "\x00" + p.tenantID + "\x00" + p.repositoryID + "\x00" + p.recoveryOwner + "\x00" + p.configuration.databaseAuthorityIdentity + "\x00" + setupPostgresURLCredentialIdentity())
}
func (p *setupReplicaReconciliationProbe) Probe(ctx context.Context) setupcore.ReplicaReconciliationProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidReplicaReconciliationProbeResult()
	}
	dataSource := p.environment("OPEN_TRESTLE_POSTGRES_URL")
	if ctx.Err() != nil {
		return setupcore.NewUnavailableReplicaReconciliationProbeResult()
	}
	observation, err := p.execute(ctx, p.configuration, dataSource)
	dataSource = ""
	if ctx.Err() != nil || errors.Is(err, postgresstore.ErrDatabaseUnavailable) || errors.Is(err, postgresstore.ErrReplicaReconciliationConformanceUnavailable) {
		return setupcore.NewUnavailableReplicaReconciliationProbeResult()
	}
	if err != nil || !validAdminDigest(observation) {
		return setupcore.NewInvalidReplicaReconciliationProbeResult()
	}
	return setupcore.NewVerifiedReplicaReconciliationProbeResult(p.authorityIdentity, observation)
}
func (p *setupReplicaReconciliationProbe) String() string {
	return "setup replica reconciliation probe"
}
func (p *setupReplicaReconciliationProbe) GoString() string {
	return "main.setupReplicaReconciliationProbe{<redacted>}"
}
func (p *setupReplicaReconciliationProbe) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}
func executeSetupReplicaReconciliation(ctx context.Context, configuration setupReplicaReconciliationConfiguration, dataSource string) (string, error) {
	if ctx == nil || ctx.Err() != nil || dataSource == "" {
		return "", postgresstore.ErrDatabaseUnavailable
	}
	database, err := postgresstore.Open(ctx, dataSource, postgresstore.PoolOptions{MaximumOpen: 4, MaximumIdle: 0, MaximumLifetime: time.Minute, MaximumIdleTime: 30 * time.Second})
	dataSource = ""
	if err != nil {
		return "", err
	}
	observation, probeErr := postgresstore.VerifyReplicaReconciliationConformance(ctx, database, configuration.databaseAuthorityIdentity, setupPostgresURLCredentialIdentity(), configuration.setupRootIdentity)
	closeErr := database.Close()
	if closeErr != nil {
		return "", postgresstore.ErrDatabaseUnavailable
	}
	if probeErr != nil {
		return "", probeErr
	}
	if observation.Validate() != nil {
		return "", postgresstore.ErrReplicaReconciliationConformanceFailed
	}
	return observation.Identity(), nil
}
