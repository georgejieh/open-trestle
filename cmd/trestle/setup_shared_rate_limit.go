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

type setupSharedRateLimitConfiguration struct{ databaseAuthorityIdentity, setupRootIdentity string }
type setupSharedRateLimitExecutor func(context.Context, setupSharedRateLimitConfiguration, string) (string, error)
type setupSharedRateLimitProbe struct {
	environment                                                        func(string) string
	configuration                                                      setupSharedRateLimitConfiguration
	planRoot, tenantID, repositoryID, recoveryOwner, authorityIdentity string
	execute                                                            setupSharedRateLimitExecutor
}

func setupPostgresURLCredentialIdentity() string {
	sum := sha256.Sum256([]byte("open-trestle/setup-postgres-url-reference/v1\x00OPEN_TRESTLE_POSTGRES_URL"))
	return hex.EncodeToString(sum[:])
}
func deriveSetupSharedRateLimitAuthority(configuration setupSharedRateLimitConfiguration) (string, error) {
	return postgresstore.SharedRateLimitConformanceAuthorityIdentity(configuration.databaseAuthorityIdentity, setupPostgresURLCredentialIdentity(), configuration.setupRootIdentity)
}
func digestSetupSharedRateLimit(value string) string {
	sum := sha256.Sum256([]byte("open-trestle/setup-shared-rate-limit/v1\x00" + value))
	return hex.EncodeToString(sum[:])
}
func newSetupSharedRateLimitProbe(environment func(string) string, plan setupcore.Plan, databaseAuthorityIdentity string, execute setupSharedRateLimitExecutor) (*setupSharedRateLimitProbe, string, error) {
	if environment == nil || execute == nil || plan.Validate() != nil {
		return nil, "", errors.New("invalid shared rate-limit setup probe")
	}
	configuration := setupSharedRateLimitConfiguration{databaseAuthorityIdentity, plan.RootIdentity()}
	authority, err := deriveSetupSharedRateLimitAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	probe := &setupSharedRateLimitProbe{environment: environment, configuration: configuration, planRoot: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), authorityIdentity: authority, execute: execute}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", errors.New("invalid shared rate-limit setup probe")
	}
	return probe, authority, nil
}
func (p *setupSharedRateLimitProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, err := deriveSetupSharedRateLimitAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func (p *setupSharedRateLimitProbe) ConfigurationIdentity() string {
	if p == nil || p.planRoot == "" || p.tenantID == "" || p.repositoryID == "" || p.recoveryOwner == "" {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" || p.configuration.setupRootIdentity != p.planRoot {
		return ""
	}
	return digestSetupSharedRateLimit("probe:" + authority + "\x00" + p.planRoot + "\x00" + p.tenantID + "\x00" + p.repositoryID + "\x00" + p.recoveryOwner + "\x00" + p.configuration.databaseAuthorityIdentity + "\x00" + setupPostgresURLCredentialIdentity())
}
func (p *setupSharedRateLimitProbe) Probe(ctx context.Context) setupcore.SharedRateLimitProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidSharedRateLimitProbeResult()
	}
	dataSource := p.environment("OPEN_TRESTLE_POSTGRES_URL")
	if ctx.Err() != nil {
		return setupcore.NewUnavailableSharedRateLimitProbeResult()
	}
	observation, err := p.execute(ctx, p.configuration, dataSource)
	dataSource = ""
	if ctx.Err() != nil || errors.Is(err, postgresstore.ErrDatabaseUnavailable) || errors.Is(err, postgresstore.ErrSharedRateLimitConformanceUnavailable) {
		return setupcore.NewUnavailableSharedRateLimitProbeResult()
	}
	if err != nil || !validAdminDigest(observation) {
		return setupcore.NewInvalidSharedRateLimitProbeResult()
	}
	return setupcore.NewVerifiedSharedRateLimitProbeResult(p.authorityIdentity, observation)
}
func (p *setupSharedRateLimitProbe) String() string { return "setup shared rate-limit probe" }
func (p *setupSharedRateLimitProbe) GoString() string {
	return "main.setupSharedRateLimitProbe{<redacted>}"
}
func (p *setupSharedRateLimitProbe) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}
func executeSetupSharedRateLimit(ctx context.Context, configuration setupSharedRateLimitConfiguration, dataSource string) (string, error) {
	if ctx == nil || ctx.Err() != nil || dataSource == "" {
		return "", postgresstore.ErrDatabaseUnavailable
	}
	database, err := postgresstore.Open(ctx, dataSource, postgresstore.PoolOptions{MaximumOpen: 4, MaximumIdle: 0, MaximumLifetime: time.Minute, MaximumIdleTime: 30 * time.Second})
	dataSource = ""
	if err != nil {
		return "", err
	}
	observation, probeErr := postgresstore.VerifySharedRateLimitConformance(ctx, database, configuration.databaseAuthorityIdentity, setupPostgresURLCredentialIdentity(), configuration.setupRootIdentity)
	closeErr := database.Close()
	if closeErr != nil {
		return "", postgresstore.ErrDatabaseUnavailable
	}
	if probeErr != nil {
		return "", probeErr
	}
	if observation.Validate() != nil {
		return "", postgresstore.ErrSharedRateLimitConformanceFailed
	}
	return observation.Identity(), nil
}
