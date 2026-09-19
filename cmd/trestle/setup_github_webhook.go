package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
	"github.com/georgejieh/open-trestle/webhook"
)

var (
	errSetupGitHubWebhookInvalid     = errors.New("invalid GitHub webhook setup conformance")
	errSetupGitHubWebhookUnavailable = errors.New("GitHub webhook setup conformance unavailable")
)

type setupGitHubWebhookConfiguration struct{ tenantID, repositoryID, keyID string }

func (c setupGitHubWebhookConfiguration) String() string { return "setup GitHub webhook configuration" }
func (c setupGitHubWebhookConfiguration) GoString() string {
	return "main.setupGitHubWebhookConfiguration{<redacted>}"
}
func (c setupGitHubWebhookConfiguration) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, c.String(), c.GoString())
}

type setupGitHubWebhookExecutor func(context.Context, setupGitHubWebhookConfiguration, []byte) (string, error)
type setupGitHubWebhookProbe struct {
	environment             func(string) string
	planRoot, recoveryOwner string
	configuration           setupGitHubWebhookConfiguration
	authorityIdentity       string
	execute                 setupGitHubWebhookExecutor
}

func setupGitHubWebhookCredentialIdentity() string {
	digest := sha256.Sum256([]byte("open-trestle/setup-github-webhook/v1\x00credential-reference:OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET"))
	return hex.EncodeToString(digest[:])
}
func webhookScope(configuration setupGitHubWebhookConfiguration) (webhook.RepositoryScope, error) {
	return webhook.NewRepositoryScope(configuration.tenantID, configuration.repositoryID)
}
func deriveSetupGitHubWebhookAuthority(configuration setupGitHubWebhookConfiguration) (string, error) {
	scope, err := webhookScope(configuration)
	if err != nil {
		return "", errSetupGitHubWebhookInvalid
	}
	identity, err := githubwebhook.ConformanceAuthorityIdentity(scope, configuration.keyID, setupGitHubWebhookCredentialIdentity())
	if err != nil {
		return "", errSetupGitHubWebhookInvalid
	}
	return identity, nil
}
func digestSetupGitHubWebhook(value string) string {
	digest := sha256.Sum256([]byte("open-trestle/setup-github-webhook/v1\x00" + value))
	return hex.EncodeToString(digest[:])
}
func newSetupGitHubWebhookProbe(environment func(string) string, plan setupcore.Plan, keyID string, execute setupGitHubWebhookExecutor) (*setupGitHubWebhookProbe, string, error) {
	if environment == nil || execute == nil || plan.Validate() != nil {
		return nil, "", errSetupGitHubWebhookInvalid
	}
	configuration := setupGitHubWebhookConfiguration{plan.TenantID(), plan.RepositoryID(), keyID}
	authority, err := deriveSetupGitHubWebhookAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	probe := &setupGitHubWebhookProbe{environment: environment, planRoot: plan.RootIdentity(), recoveryOwner: plan.RecoveryOwner(), configuration: configuration, authorityIdentity: authority, execute: execute}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", errSetupGitHubWebhookInvalid
	}
	return probe, authority, nil
}
func (p *setupGitHubWebhookProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, err := deriveSetupGitHubWebhookAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func (p *setupGitHubWebhookProbe) ConfigurationIdentity() string {
	if p == nil || p.planRoot == "" || p.recoveryOwner == "" {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" {
		return ""
	}
	return digestSetupGitHubWebhook("probe:" + authority + "\x00" + p.planRoot + "\x00" + p.configuration.tenantID + "\x00" + p.configuration.repositoryID + "\x00" + p.recoveryOwner + "\x00separate-from:OPEN_TRESTLE_GITHUB_SETUP_TOKEN,OPEN_TRESTLE_GITHUB_API_TOKEN,OPEN_TRESTLE_SETUP_TOKEN,OPEN_TRESTLE_API_TOKEN,OPEN_TRESTLE_OBSERVER_TOKEN,OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN")
}
func (p *setupGitHubWebhookProbe) Probe(ctx context.Context) setupcore.WebhookProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidWebhookProbeResult()
	}
	secretValue := p.environment("OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET")
	secret := []byte(secretValue)
	secretValue = ""
	others := []string{p.environment("OPEN_TRESTLE_GITHUB_SETUP_TOKEN"), p.environment("OPEN_TRESTLE_GITHUB_API_TOKEN"), p.environment("OPEN_TRESTLE_SETUP_TOKEN"), p.environment("OPEN_TRESTLE_API_TOKEN"), p.environment("OPEN_TRESTLE_OBSERVER_TOKEN"), p.environment("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN")}
	if ctx.Err() != nil {
		clear(secret)
		clear(others)
		return setupcore.NewUnavailableWebhookProbeResult()
	}
	invalid := githubwebhook.ValidateRuntimeSecret(secret) != nil
	for _, other := range others {
		invalid = invalid || sameSetupWebhookSecret(secret, other)
	}
	if invalid {
		clear(secret)
		clear(others)
		return setupcore.NewInvalidWebhookProbeResult()
	}
	observation, err := p.execute(ctx, p.configuration, secret)
	clear(secret)
	clear(others)
	if ctx.Err() != nil || errors.Is(err, errSetupGitHubWebhookUnavailable) {
		return setupcore.NewUnavailableWebhookProbeResult()
	}
	if err != nil || !validAdminDigest(observation) {
		return setupcore.NewInvalidWebhookProbeResult()
	}
	return setupcore.NewVerifiedWebhookProbeResult(p.authorityIdentity, observation)
}
func sameSetupWebhookSecret(left []byte, right string) bool {
	if right == "" || len(left) != len(right) {
		return false
	}
	rightBytes := []byte(right)
	defer clear(rightBytes)
	return subtle.ConstantTimeCompare(left, rightBytes) == 1
}
func (p *setupGitHubWebhookProbe) String() string { return "setup GitHub webhook probe" }
func (p *setupGitHubWebhookProbe) GoString() string {
	return "main.setupGitHubWebhookProbe{<redacted>}"
}
func (p *setupGitHubWebhookProbe) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}

func executeSetupGitHubWebhook(ctx context.Context, configuration setupGitHubWebhookConfiguration, secret []byte) (string, error) {
	return executeSetupGitHubWebhookWithTemporaryDirectory(ctx, configuration, secret, func() (string, error) { return os.MkdirTemp("", "open-trestle-webhook-") })
}
func executeSetupGitHubWebhookWithTemporaryDirectory(ctx context.Context, configuration setupGitHubWebhookConfiguration, secret []byte, create func() (string, error)) (string, error) {
	defer clear(secret)
	if ctx == nil || ctx.Err() != nil || create == nil || githubwebhook.ValidateRuntimeSecret(secret) != nil {
		return "", errSetupGitHubWebhookInvalid
	}
	authority, err := deriveSetupGitHubWebhookAuthority(configuration)
	if err != nil || authority == "" {
		return "", errSetupGitHubWebhookInvalid
	}
	root, err := create()
	if err != nil {
		return "", errSetupGitHubWebhookUnavailable
	}
	absolute, pathErr := filepath.Abs(root)
	information, statErr := os.Lstat(absolute)
	if pathErr != nil || statErr != nil || root != absolute || !information.IsDir() || information.Mode().Perm()&0o077 != 0 || information.Mode()&os.ModeSymlink != 0 {
		if pathErr == nil && statErr == nil && information.IsDir() && information.Mode()&os.ModeSymlink == 0 {
			_ = safeRemoveWebhookTemporaryDirectory(absolute, information)
		}
		return "", errSetupGitHubWebhookUnavailable
	}
	store, err := webhook.NewFileStore(absolute)
	if err != nil {
		_ = safeRemoveWebhookTemporaryDirectory(absolute, information)
		return "", errSetupGitHubWebhookUnavailable
	}
	scope, _ := webhookScope(configuration)
	observation, probeErr := githubwebhook.VerifyConformance(ctx, secret, scope, configuration.keyID, setupGitHubWebhookCredentialIdentity(), store)
	closeErr := store.Close()
	cleanupErr := safeRemoveWebhookTemporaryDirectory(absolute, information)
	if ctx.Err() != nil || closeErr != nil || cleanupErr != nil {
		return "", errSetupGitHubWebhookUnavailable
	}
	if probeErr != nil {
		if errors.Is(probeErr, githubwebhook.ErrInvalidWebhookConformance) || errors.Is(probeErr, githubwebhook.ErrWebhookConformanceFailed) {
			return "", errSetupGitHubWebhookInvalid
		}
		return "", errSetupGitHubWebhookUnavailable
	}
	if observation.Validate() != nil || observation.AuthorityIdentity() != authority {
		return "", errSetupGitHubWebhookInvalid
	}
	return observation.Identity(), nil
}
func safeRemoveWebhookTemporaryDirectory(root string, expected os.FileInfo) error {
	matchesRoot := func() bool {
		current, err := os.Lstat(root)
		return err == nil && expected != nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0 && os.SameFile(expected, current)
	}
	if !matchesRoot() {
		return errSetupGitHubWebhookUnavailable
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 2 {
		return errSetupGitHubWebhookUnavailable
	}
	lockCount, deliveryCount := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		recognized := false
		if name == ".inbox-writer.lock" {
			lockCount++
			recognized = true
		} else if strings.HasSuffix(name, ".delivery.json") {
			deliveryCount++
			recognized = true
		}
		information, infoErr := entry.Info()
		if infoErr != nil || !recognized || information.Mode()&os.ModeSymlink != 0 || !information.Mode().IsRegular() || lockCount > 1 || deliveryCount > 1 || !matchesRoot() {
			return errSetupGitHubWebhookUnavailable
		}
		if err = os.Remove(filepath.Join(root, name)); err != nil {
			return errSetupGitHubWebhookUnavailable
		}
	}
	if !matchesRoot() {
		return errSetupGitHubWebhookUnavailable
	}
	directory, err := os.Open(root)
	if err != nil {
		return errSetupGitHubWebhookUnavailable
	}
	current, statErr := directory.Stat()
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if statErr != nil || !os.SameFile(expected, current) || syncErr != nil || closeErr != nil || !matchesRoot() {
		return errSetupGitHubWebhookUnavailable
	}
	if err = os.Remove(root); err != nil {
		return errSetupGitHubWebhookUnavailable
	}
	if _, err = os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errSetupGitHubWebhookUnavailable
	}
	return nil
}
