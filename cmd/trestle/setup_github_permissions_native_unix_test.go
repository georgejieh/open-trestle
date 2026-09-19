//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func runSetupGitHubPermissionNativeTest(t *testing.T, name string) {
	t.Helper()
	switch name {
	case "probe-defers-and-separates", "probe-authority-and-shared-token", "probe-classifies-outcomes", "cli-permission-receipt", "tui-permission-receipt", "probe-changed-configuration", "cli-webhook-after-permission", "tui-webhook-after-permission":
	default:
		t.Fatal("unknown native permission companion case")
	}
	f := setupBrokerBoundaryNew(t)
	owner, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	if name == "cli-permission-receipt" || name == "cli-webhook-after-permission" {
		f.setenv(t)
		var stdout, stderr bytes.Buffer
		if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", f.state}, &stdout, &stderr, setupBrokerBoundaryClock{f.at}); code != 0 {
			t.Fatal("actual CLI current initialization failed")
		}
		plan := f.current(t)
		inference, err := newSetupLocalInferenceFactory(func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		postgres, err := newSetupPostgresStorageProbe(func(string) string { return "" }, executeSetupPostgresStorage)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		permissionExecutor := func(ctx context.Context, c setupGitHubPermissionConfiguration, user string, broker *githubadapter.InstallationTokenBroker) (string, error) {
			calls++
			return executeSetupGitHubPermission(ctx, c, user, broker)
		}
		stdout.Reset()
		stderr.Reset()
		code := runSetupWithDependencies(f.cliArgs(t), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(time.Second)}, inference, postgres, executeSetupKMS, executeSetupEnvelopeStorage, permissionExecutor, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle)
		if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"integration_permissions_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
			t.Fatal("actual CLI native integration receipt or exact executor count failed")
		}
		receipt, err := setupcore.DecodeCheckReceipt(bytes.TrimSpace(stdout.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		setupBrokerBoundaryReceipt(t, receipt, plan, setupcore.CheckPassed)
		f.effects(t, 1, 1, -1)
		f.accepted(t, 3)
		if name == "cli-permission-receipt" {
			return
		}
		plan = f.current(t)
		configuration := setupGitHubWebhookConfiguration{plan.TenantID(), plan.RepositoryID(), "primary-2026"}
		authority, err := deriveSetupGitHubWebhookAuthority(configuration)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		webhookCalls := 0
		webhookExecutor := func(_ context.Context, got setupGitHubWebhookConfiguration, secret []byte) (string, error) {
			webhookCalls++
			if got != configuration || string(secret) != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
				t.Fatal("wrong webhook input")
			}
			// Original webhook conformance wiring seam, not permission evidence.
			return strings.Repeat("e", 64), nil
		}
		stdout.Reset()
		stderr.Reset()
		code = runSetupWithDependencies([]string{"check", "webhook", "--state", f.state, "--approve-webhook-authority-identity", authority, "--github-webhook-key-id", configuration.keyID, "--approved-by", "owner"}, &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(2 * time.Second)}, inference, postgres, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, webhookExecutor, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle)
		if code != 0 || stderr.Len() != 0 || webhookCalls != 1 || !strings.Contains(stdout.String(), `"key":"webhook_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
			t.Fatal("webhook command lost native permission prerequisite or conformance wiring")
		}
		f.effects(t, 1, 1, -1)
		return
	}

	plan := f.initialize(t, true, "tenant-a", "repo-a")
	reads, calls := 0, 0
	var webhookPhase atomic.Bool
	var publicationComparisons atomic.Int32
	environment := f.getenv
	switch name {
	case "probe-defers-and-separates":
		environment = func(name string) string {
			// The original six reads remain dedicated-user plus five comparisons;
			// the separate lazy App read is independently counted by the fixture.
			if name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
				reads++
			}
			return f.getenv(name)
		}
	case "probe-authority-and-shared-token":
		environment = func(string) string { reads++; return "same-token" }
	case "probe-changed-configuration":
		environment = func(string) string { reads++; return "token" }
	case "tui-webhook-after-permission":
		environment = func(name string) string {
			if name == "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN" && webhookPhase.Load() {
				publicationComparisons.Add(1)
				return "synthetic-publication-comparison-only"
			}
			if name == "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET" {
				return "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
			}
			return f.getenv(name)
		}
	}
	session, err := newSetupGitHubPermissionSession(owner, f.configuration, environment, githubadapter.SystemBrokerClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if session.Close() != nil {
			t.Error("native companion session cleanup failed")
		}
	})
	configuration := setupGitHubPermissionConfiguration{host: f.host(t), session: session, expectedBrokerAuthority: f.configuration.AuthorityIdentity(), allowTokenCreation: true}
	executor := func(ctx context.Context, got setupGitHubPermissionConfiguration, user string, broker *githubadapter.InstallationTokenBroker) (string, error) {
		calls++
		if got.host.broker.AuthorityIdentity() != f.configuration.AuthorityIdentity() || got.host.broker.Authority().Configuration().RepositoryFullName != "owner/repo" || user != setupBrokerBoundaryUser || broker == nil || broker.Purpose() != githubadapter.IssuancePurposeSetup {
			t.Fatal("crossed permission executor input")
		}
		return executeSetupGitHubPermission(ctx, got, user, broker)
	}
	probe, authority, err := newSetupGitHubPermissionProbe(environment, plan, configuration, executor)
	if err != nil || reads != 0 || calls != 0 {
		t.Fatal("probe constructor consumed credentials or executed")
	}
	f.noEffects(t)
	switch name {
	case "probe-defers-and-separates":
		checker, err := setupcore.NewIntegrationPermissionChecker(plan, authority, "owner", probe)
		if err != nil {
			t.Fatal(err)
		}
		if result := checker.Check(owner, plan); result.State() != setupcore.CheckPassed || reads != 6 || calls != 1 {
			t.Fatal("native probe did not preserve dedicated/comparison reads and single execution")
		}
		f.effects(t, 1, 1, 1)
		f.accepted(t, 3)
		token, _ := githubadapter.NewToken([]byte("very-secret-token"))
		formatted := fmt.Sprintf("%#v %#v", probe, &setupGitHubTokenProvider{token})
		if strings.Contains(formatted, "very-secret-token") || strings.Contains(formatted, "owner/repo") || strings.Contains(formatted, "api.github") {
			t.Fatal("probe formatter leaked")
		}
	case "probe-authority-and-shared-token":
		checker, err := setupcore.NewIntegrationPermissionChecker(plan, strings.Repeat("f", 64), "owner", probe)
		if err != nil {
			t.Fatal(err)
		}
		if result := checker.Check(owner, plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
			t.Fatal("wrong permission authority reached credentials")
		}
		checker, err = setupcore.NewIntegrationPermissionChecker(plan, authority, "owner", probe)
		if err != nil {
			t.Fatal(err)
		}
		if result := checker.Check(owner, plan); result.State() != setupcore.CheckBlocked || reads != 6 || calls != 0 {
			t.Fatal("shared token reached executor")
		}
		f.noEffects(t)
	case "probe-changed-configuration":
		checker, err := setupcore.NewIntegrationPermissionChecker(plan, authority, "owner", probe)
		if err != nil {
			t.Fatal(err)
		}
		// A nonzero legacy member now creates an invalid mixed current shape.
		probe.configuration.installationID++
		if result := checker.Check(owner, plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
			t.Fatal("changed configuration reached credentials")
		}
		f.noEffects(t)
	case "probe-classifies-outcomes":
		for _, test := range []struct {
			err  error
			want setupcore.CheckState
		}{
			{githubadapter.ErrPermissionUnavailable, setupcore.CheckUnavailable},
			{githubadapter.ErrPermissionDenied, setupcore.CheckBlocked},
			{githubadapter.ErrPermissionMismatch, setupcore.CheckBlocked},
			{errors.New("unknown"), setupcore.CheckBlocked},
		} {
			// Preserve the original closed-error mapping oracle. Each wrapper
			// first requires the PRODUCTION native executor to succeed, then
			// discards that observation and supplies the negative boundary error.
			// This is not proof that an issuer returned that error, and cannot
			// manufacture a passing observation or receipt.
			probe, authority, err := newSetupGitHubPermissionProbe(environment, plan, configuration, func(ctx context.Context, got setupGitHubPermissionConfiguration, user string, broker *githubadapter.InstallationTokenBroker) (string, error) {
				if _, nativeErr := executeSetupGitHubPermission(ctx, got, user, broker); nativeErr != nil {
					t.Fatal("native classification prerequisite failed")
				}
				return "", test.err
			})
			if err != nil {
				t.Fatal(err)
			}
			checker, err := setupcore.NewIntegrationPermissionChecker(plan, authority, "owner", probe)
			if err != nil {
				t.Fatal(err)
			}
			if result := checker.Check(owner, plan); result.State() != test.want {
				t.Fatal("permission error classification changed")
			}
		}
		f.effects(t, 4, 1, 1)
		f.accepted(t, 3)
	case "tui-permission-receipt", "tui-webhook-after-permission":
		state, err := setupcore.OpenStateFile(f.state)
		if err != nil {
			t.Fatal(err)
		}
		defer state.Close()
		service := &setupTUIService{state: state, clock: setupBrokerBoundaryClock{f.at.Add(time.Second)}, getenv: environment,
			githubPermissionExecutor: executor, githubPermissionSession: session, githubPermissionHost: configuration.host,
			githubBrokerAuthorityIdentity: configuration.expectedBrokerAuthority, githubAllowTokenCreation: true,
			integrationPermissionAuthorityIdentity: authority, integrationApprovedBy: "owner"}
		defer func() {
			if service.Close() != nil {
				t.Error("TUI native companion cleanup failed")
			}
		}()
		next, receipt, err := service.RunCheck(owner, setupcore.CheckIntegrationPermissionsValidated, plan.Identity())
		if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
			t.Fatal("TUI service native permission receipt failed")
		}
		setupBrokerBoundaryReceipt(t, receipt, plan, setupcore.CheckPassed)
		f.effects(t, 1, 1, 1)
		f.accepted(t, 3)
		if name == "tui-permission-receipt" {
			return
		}
		webhookConfiguration := setupGitHubWebhookConfiguration{next.TenantID(), next.RepositoryID(), "primary-2026"}
		webhookAuthority, err := deriveSetupGitHubWebhookAuthority(webhookConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		webhookCalls := 0
		service.clock = setupBrokerBoundaryClock{f.at.Add(2 * time.Second)}
		service.githubWebhookExecutor = func(context.Context, setupGitHubWebhookConfiguration, []byte) (string, error) {
			webhookCalls++
			return strings.Repeat("e", 64), nil
		}
		service.webhookAuthorityIdentity = webhookAuthority
		service.githubWebhookKeyID = webhookConfiguration.keyID
		service.webhookApprovedBy = "owner"
		if publicationComparisons.Load() != 0 {
			t.Fatal("permission phase read publication comparison")
		}
		webhookPhase.Store(true)
		_, receipt, err = service.RunCheck(owner, setupcore.CheckWebhookValidated, next.Identity())
		if err != nil || receipt.State() != setupcore.CheckPassed || webhookCalls != 1 {
			t.Fatal("TUI webhook lost native permission prerequisite")
		}
		if publicationComparisons.Load() != 1 {
			t.Fatal("webhook did not retain its publication-token separation check")
		}
		f.effects(t, 1, 1, 1)
	}
}
