package main

import (
	"context"
	"testing"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func setupGitHubPermissionConfigFixture() setupGitHubPermissionConfiguration {
	return setupGitHubPermissionConfiguration{apiEndpoint: "https://api.github.com", apiVersion: "2026-03-10", installationID: 42, repositoryFullName: "owner/repo"}
}

// Legacy administrative identity remains portable. It is no longer an active
// setup executor. Native success/classification assertions live in companions
// because protected local ownership is unavailable on non-Unix platforms.
func assertSetupGitHubPermissionLegacyIdentityOnly(t *testing.T) {
	t.Helper()
	configuration := setupGitHubPermissionConfigFixture()
	authority, err := deriveSetupGitHubPermissionAuthority(configuration)
	expected, expectedErr := githubadapter.PermissionAuthorityIdentity(configuration.apiEndpoint, configuration.apiVersion, configuration.installationID, configuration.repositoryFullName, setupGitHubPermissionUserCredentialIdentity(), setupGitHubPermissionRuntimeCredentialIdentity(), setupGitHubPermissionTimeout)
	if err != nil || expectedErr != nil || authority != expected || !validSetupGitHubPermissionConfiguration(configuration) {
		t.Fatal("legacy pure permission identity changed")
	}
	changed := configuration
	changed.installationID++
	other, err := deriveSetupGitHubPermissionAuthority(changed)
	if err != nil || other == authority {
		t.Fatal("legacy identity lost installation binding")
	}
	plan, err := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	if err != nil {
		t.Fatal(err)
	}
	reads, calls := 0, 0
	probe, _, err := newSetupGitHubPermissionProbe(func(string) string {
		reads++
		return "setup-user-token"
	}, plan, configuration, func(context.Context, setupGitHubPermissionConfiguration, string, *githubadapter.InstallationTokenBroker) (string, error) {
		calls++
		return "", githubadapter.ErrPermissionDenied
	})
	if err == nil || probe != nil || reads != 0 || calls != 0 {
		t.Fatal("legacy identity-only configuration reached active credentials or executor")
	}
}

func TestSetupGitHubPermissionProbeDefersAndSeparatesToken(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "probe-defers-and-separates")
}
func TestSetupGitHubPermissionProbeRejectsAuthorityAndSharedTokenBeforeInspection(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "probe-authority-and-shared-token")
}
func TestSetupGitHubPermissionProbeClassifiesOutcomes(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "probe-classifies-outcomes")
}
func TestSetupCLIRecordsExactIntegrationPermissionReceipt(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "cli-permission-receipt")
}
func TestSetupTUIServiceRunsGitHubIntegrationPermissionCheck(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "tui-permission-receipt")
}
func TestSetupGitHubPermissionCheckerFencesChangedConfigurationBeforeTokenRead(t *testing.T) {
	assertSetupGitHubPermissionLegacyIdentityOnly(t)
	runSetupGitHubPermissionNativeTest(t, "probe-changed-configuration")
}
