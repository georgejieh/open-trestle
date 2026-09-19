package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

const setupGitHubPermissionTimeout = 30 * time.Second

type setupGitHubPermissionConfiguration struct {
	// Retained only for pure legacy administrative identity derivation.
	apiEndpoint, apiVersion string
	installationID          uint64
	repositoryFullName      string
	host                    setupGitHubPermissionHostConfiguration
	session                 *setupGitHubPermissionSession
	expectedBrokerAuthority string
	allowTokenCreation      bool
}

func (c setupGitHubPermissionConfiguration) String() string {
	return "[redacted setup GitHub permission configuration]"
}
func (c setupGitHubPermissionConfiguration) GoString() string { return c.String() }
func (c setupGitHubPermissionConfiguration) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

type setupGitHubPermissionExecutor func(context.Context, setupGitHubPermissionConfiguration, string, *githubadapter.InstallationTokenBroker) (string, error)
type setupGitHubPermissionProbe struct {
	environment                                     func(string) string
	planRoot, tenantID, repositoryID, recoveryOwner string
	configuration                                   setupGitHubPermissionConfiguration
	authorityIdentity                               string
	execute                                         setupGitHubPermissionExecutor
}

func setupGitHubPermissionUserCredentialIdentity() string {
	return digestSetupGitHubPermission("credential-reference:OPEN_TRESTLE_GITHUB_SETUP_TOKEN")
}
func setupGitHubPermissionRuntimeCredentialIdentity() string {
	return digestSetupGitHubPermission("credential-reference:OPEN_TRESTLE_GITHUB_API_TOKEN")
}
func digestSetupGitHubPermission(value string) string {
	sum := sha256.Sum256([]byte("open-trestle/setup-github-permission/v1\x00" + value))
	return hex.EncodeToString(sum[:])
}

func validSetupGitHubPermissionConfiguration(c setupGitHubPermissionConfiguration) bool {
	_, err := deriveSetupGitHubPermissionAuthority(c)
	return err == nil
}

func deriveSetupGitHubPermissionAuthority(c setupGitHubPermissionConfiguration) (string, error) {
	if !c.host.configured && c.host.Validate() == nil && c.session == nil && c.expectedBrokerAuthority == "" && !c.allowTokenCreation {
		return githubadapter.PermissionAuthorityIdentity(c.apiEndpoint, c.apiVersion, c.installationID, c.repositoryFullName, setupGitHubPermissionUserCredentialIdentity(), setupGitHubPermissionRuntimeCredentialIdentity(), setupGitHubPermissionTimeout)
	}
	if c.apiEndpoint != "" || c.apiVersion != "" || c.installationID != 0 || c.repositoryFullName != "" ||
		!c.host.configured || c.host.Validate() != nil || c.session == nil || !c.allowTokenCreation ||
		c.expectedBrokerAuthority != c.host.expectedBrokerAuthority || c.expectedBrokerAuthority != c.host.broker.AuthorityIdentity() ||
		c.session.configuration.Validate() != nil || c.session.authorityIdentity != c.host.broker.AuthorityIdentity() ||
		c.session.configuration.AuthorityIdentity() != c.host.broker.AuthorityIdentity() {
		return "", githubadapter.ErrInvalidBrokerConfig
	}
	return githubadapter.BrokeredPermissionAuthorityIdentity(c.host.broker.Authority(), setupGitHubPermissionUserCredentialIdentity(), setupGitHubPermissionTimeout)
}

func newSetupGitHubPermissionProbe(environment func(string) string, plan setupcore.Plan, configuration setupGitHubPermissionConfiguration, execute setupGitHubPermissionExecutor) (*setupGitHubPermissionProbe, string, error) {
	if environment == nil || execute == nil || plan.Validate() != nil || !configuration.host.configured || configuration.session == nil {
		return nil, "", githubadapter.ErrInvalidBrokerConfig
	}
	authority, err := deriveSetupGitHubPermissionAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	bound := configuration.host.broker.Authority().Configuration()
	if plan.TenantID() != bound.TenantID || plan.RepositoryID() != bound.RepositoryID {
		return nil, "", githubadapter.ErrBrokerMismatch
	}
	probe := &setupGitHubPermissionProbe{
		environment: environment, planRoot: plan.RootIdentity(), tenantID: plan.TenantID(),
		repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(),
		configuration: configuration, authorityIdentity: authority, execute: execute,
	}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", githubadapter.ErrInvalidBrokerConfig
	}
	return probe, authority, nil
}

func (p *setupGitHubPermissionProbe) AuthorityIdentity() string {
	if p == nil || !p.configuration.host.configured || p.configuration.session == nil {
		return ""
	}
	authority, err := deriveSetupGitHubPermissionAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}

func (p *setupGitHubPermissionProbe) ConfigurationIdentity() string {
	if p == nil || !validAdminDigest(p.planRoot) || !validSetupApprovalLabel(p.recoveryOwner) {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" {
		return ""
	}
	c := p.configuration
	bound := c.host.broker.Authority().Configuration()
	if p.tenantID != bound.TenantID || p.repositoryID != bound.RepositoryID {
		return ""
	}
	lane, err := githubadapter.NewIssuanceAuthority(c.host.broker.Authority(), githubadapter.IssuancePurposeSetup)
	if err != nil {
		return ""
	}
	values := [15]any{
		"probe", 2, authority, c.host.broker.AuthorityIdentity(), lane.Identity(),
		setupGitHubPermissionUserCredentialIdentity(), p.planRoot, p.tenantID, p.repositoryID, p.recoveryOwner,
		c.host.expectedBrokerAuthority, c.expectedBrokerAuthority, c.allowTokenCreation,
		[5]string{"OPEN_TRESTLE_GITHUB_API_TOKEN", "OPEN_TRESTLE_SETUP_TOKEN", "OPEN_TRESTLE_API_TOKEN", "OPEN_TRESTLE_OBSERVER_TOKEN", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET"},
		"reject-static-token;setup-purpose;owner-lifetime;foreground-demand-renewal;fresh-generation-on-restart",
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("open-trestle/setup-github-permission/v2\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

func (p *setupGitHubPermissionProbe) Probe(ctx context.Context) setupcore.IntegrationPermissionProbeResult {
	if setupGitHubPermissionNil(ctx) {
		return setupcore.NewInvalidIntegrationPermissionProbeResult()
	}
	if ctx.Err() != nil {
		return setupcore.NewUnavailableIntegrationPermissionProbeResult()
	}
	if p == nil || p.environment == nil || p.execute == nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidIntegrationPermissionProbeResult()
	}
	setupToken := p.environment("OPEN_TRESTLE_GITHUB_SETUP_TOKEN")
	staticToken := p.environment("OPEN_TRESTLE_GITHUB_API_TOKEN")
	setupAuthorityToken := p.environment("OPEN_TRESTLE_SETUP_TOKEN")
	apiToken := p.environment("OPEN_TRESTLE_API_TOKEN")
	observerToken := p.environment("OPEN_TRESTLE_OBSERVER_TOKEN")
	webhookSecret := p.environment("OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET")
	if ctx.Err() != nil {
		return setupcore.NewUnavailableIntegrationPermissionProbeResult()
	}
	if setupToken == "" || staticToken != "" || sameSetupGitHubToken(setupToken, staticToken) ||
		sameSetupGitHubToken(setupToken, setupAuthorityToken) || sameSetupGitHubToken(setupToken, apiToken) ||
		sameSetupGitHubToken(setupToken, observerToken) || sameSetupGitHubToken(setupToken, webhookSecret) {
		return setupcore.NewInvalidIntegrationPermissionProbeResult()
	}
	staticToken, setupAuthorityToken, apiToken, observerToken, webhookSecret = "", "", "", "", ""
	broker, err := p.configuration.session.broker(ctx, p.configuration.expectedBrokerAuthority)
	observation := ""
	if err == nil {
		observation, err = p.execute(ctx, p.configuration, setupToken, broker)
	}
	setupToken = ""
	if ctx.Err() != nil {
		return setupcore.NewUnavailableIntegrationPermissionProbeResult()
	}
	if err == nil {
		if !validAdminDigest(observation) {
			return setupcore.NewInvalidIntegrationPermissionProbeResult()
		}
		return setupcore.NewVerifiedIntegrationPermissionProbeResult(p.authorityIdentity, observation)
	}
	if errors.Is(err, githubadapter.ErrPermissionUnavailable) || errors.Is(err, githubadapter.ErrBrokerUnavailable) || errors.Is(err, githubadapter.ErrBrokerCloseIncomplete) {
		return setupcore.NewUnavailableIntegrationPermissionProbeResult()
	}
	return setupcore.NewInvalidIntegrationPermissionProbeResult()
}

func sameSetupGitHubToken(left, right string) bool {
	return right != "" && len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
func (p *setupGitHubPermissionProbe) String() string {
	return "[redacted setup GitHub permission probe]"
}
func (p *setupGitHubPermissionProbe) GoString() string { return p.String() }
func (p *setupGitHubPermissionProbe) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

type setupGitHubTokenProvider struct{ token githubadapter.Token }

func (p *setupGitHubTokenProvider) Retrieve(ctx context.Context) (githubadapter.Token, error) {
	if p == nil || setupGitHubPermissionNil(ctx) || ctx.Err() != nil || p.token.Validate() != nil {
		return githubadapter.Token{}, githubadapter.ErrInvalidToken
	}
	return p.token, nil
}
func (p *setupGitHubTokenProvider) String() string { return "setup GitHub token provider" }
func (p *setupGitHubTokenProvider) GoString() string {
	return "main.setupGitHubTokenProvider{<redacted>}"
}
func (p *setupGitHubTokenProvider) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}

func executeSetupGitHubPermission(ctx context.Context, configuration setupGitHubPermissionConfiguration, userTokenValue string, broker *githubadapter.InstallationTokenBroker) (string, error) {
	if setupGitHubPermissionNil(ctx) || ctx.Err() != nil {
		return "", githubadapter.ErrPermissionUnavailable
	}
	if broker == nil {
		return "", githubadapter.ErrPermissionMismatch
	}
	authority, err := deriveSetupGitHubPermissionAuthority(configuration)
	if err != nil || !configuration.host.configured || configuration.session == nil || broker.Validate() != nil ||
		broker.AuthorityIdentity() != configuration.host.broker.AuthorityIdentity() || broker.Purpose() != githubadapter.IssuancePurposeSetup {
		return "", githubadapter.ErrPermissionMismatch
	}
	userRaw := []byte(userTokenValue)
	userToken, err := githubadapter.NewToken(userRaw)
	clear(userRaw)
	if err != nil {
		return "", githubadapter.ErrPermissionDenied
	}
	bound := configuration.host.broker.Authority().Configuration()
	inspector, err := githubadapter.NewPermissionInspector(githubadapter.PermissionConfig{
		APIEndpoint: bound.APIEndpoint, APIVersion: bound.APIVersion, InstallationID: bound.InstallationID,
		RepositoryFullName: bound.RepositoryFullName, UserCredentialIdentity: setupGitHubPermissionUserCredentialIdentity(),
		UserCredentials: &setupGitHubTokenProvider{token: userToken}, RuntimeBroker: broker,
		RuntimeCredentials: nil, RuntimeCredentialIdentity: "", Timeout: setupGitHubPermissionTimeout,
	})
	if err != nil {
		return "", err
	}
	if inspector.AuthorityIdentity() != authority {
		return "", githubadapter.ErrPermissionMismatch
	}
	// Native Inspect registers its complete operation with this broker BEFORE
	// user visibility GET. Owner cancellation therefore covers all Inspect I/O.
	observation, err := inspector.Inspect(ctx)
	if err != nil {
		return "", err
	}
	if observation.Validate() != nil || observation.AuthorityIdentity() != authority {
		return "", githubadapter.ErrPermissionMismatch
	}
	return observation.Identity(), nil
}
