package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestSetupGitHubWebhookProbeDefersSecretAndBindsScope(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repository-a", "owner", setupTimeCLI())
	environmentCalls, executeCalls := 0, 0
	environment := func(name string) string {
		environmentCalls++
		if name == "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET" {
			return "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
		}
		return "distinct-" + name
	}
	execute := func(_ context.Context, configuration setupGitHubWebhookConfiguration, secret []byte) (string, error) {
		executeCalls++
		if configuration.tenantID != "tenant-a" || configuration.repositoryID != "repository-a" || configuration.keyID != "primary-2026" || string(secret) != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
			t.Fatalf("configuration=%#v secret=%q", configuration, secret)
		}
		return strings.Repeat("d", 64), nil
	}
	probe, authority, err := newSetupGitHubWebhookProbe(environment, plan, "primary-2026", execute)
	if err != nil || probe.ConfigurationIdentity() == "" || probe.AuthorityIdentity() != authority {
		t.Fatalf("probe=%#v authority=%s err=%v", probe, authority, err)
	}
	if environmentCalls != 0 || executeCalls != 0 {
		t.Fatal("constructor resolved secret or executed conformance")
	}
	result := probe.Probe(context.Background())
	if environmentCalls != 7 || executeCalls != 1 || result != setupcore.NewVerifiedWebhookProbeResult(authority, strings.Repeat("d", 64)) {
		t.Fatalf("calls=%d/%d result=%#v", environmentCalls, executeCalls, result)
	}
	other, _ := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repository-b", "owner", setupTimeCLI())
	_, changedAuthority, err := newSetupGitHubWebhookProbe(environment, other, "primary-2026", execute)
	if err != nil || changedAuthority == authority {
		t.Fatal("repository scope not bound")
	}
}

func TestSetupGitHubWebhookProbeRejectsMissingWeakAndReusedSecrets(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repository-a", "owner", setupTimeCLI())
	for _, test := range []struct{ name, secret, other string }{{"missing", "", ""}, {"weak", "short", ""}, {"repeated", strings.Repeat("a", 64), ""}, {"uppercase", strings.ToUpper("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), ""}, {"reused", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			environment := func(name string) string {
				if name == "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET" {
					return test.secret
				}
				if name == "OPEN_TRESTLE_API_TOKEN" {
					return test.other
				}
				return ""
			}
			probe, _, err := newSetupGitHubWebhookProbe(environment, plan, "primary-2026", func(context.Context, setupGitHubWebhookConfiguration, []byte) (string, error) {
				calls++
				return strings.Repeat("d", 64), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if result := probe.Probe(context.Background()); result != setupcore.NewInvalidWebhookProbeResult() || calls != 0 {
				t.Fatalf("result=%#v calls=%d", result, calls)
			}
		})
	}
}

func TestExecuteSetupGitHubWebhookConformanceCleansDisposableStoreAndSecret(t *testing.T) {
	parent := t.TempDir()
	var created string
	create := func() (string, error) {
		var err error
		created, err = os.MkdirTemp(parent, "probe-")
		return created, err
	}
	secret := []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	configuration := setupGitHubWebhookConfiguration{"tenant-a", "repository-a", "primary-2026"}
	observation, err := executeSetupGitHubWebhookWithTemporaryDirectory(context.Background(), configuration, secret, create)
	if err != nil || !validAdminDigest(observation) {
		t.Fatalf("observation=%s err=%v", observation, err)
	}
	if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary store remains: %v", err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("parent entries=%v err=%v", entries, err)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("caller secret was not cleared")
		}
	}
}

func TestExecuteSetupGitHubWebhookCleansAfterInvalidSecret(t *testing.T) {
	parent := t.TempDir()
	var created string
	create := func() (string, error) {
		var err error
		created, err = os.MkdirTemp(parent, "probe-")
		return created, err
	}
	secret := []byte("short")
	configuration := setupGitHubWebhookConfiguration{"tenant-a", "repository-a", "primary-2026"}
	if _, err := executeSetupGitHubWebhookWithTemporaryDirectory(context.Background(), configuration, secret, create); !errors.Is(err, errSetupGitHubWebhookInvalid) {
		t.Fatalf("error=%v", err)
	}
	if created != "" {
		t.Fatal("weak secret created disposable storage")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("parent entries=%v err=%v", entries, err)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("caller secret was not cleared")
		}
	}
}

func TestSetupGitHubWebhookAuthorityMatchesAdapter(t *testing.T) {
	configuration := setupGitHubWebhookConfiguration{"tenant-a", "repository-a", "primary-2026"}
	authority, err := deriveSetupGitHubWebhookAuthority(configuration)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := webhookScope(configuration)
	expected, err := githubwebhook.ConformanceAuthorityIdentity(scope, configuration.keyID, setupGitHubWebhookCredentialIdentity())
	if err != nil || authority != expected {
		t.Fatalf("authority=%s expected=%s err=%v", authority, expected, err)
	}
}

func TestWebhookTemporaryCleanupDoesNotRecursivelyDeleteUnexpectedOrReplacedContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "probe")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	expected, _ := os.Lstat(root)
	unexpected := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(unexpected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safeRemoveWebhookTemporaryDirectory(root, expected); !errors.Is(err, errSetupGitHubWebhookUnavailable) {
		t.Fatalf("unexpected error=%v", err)
	}
	if _, err := os.Lstat(unexpected); err != nil {
		t.Fatalf("unexpected file removed: %v", err)
	}
	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}
	old := root + "-old"
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safeRemoveWebhookTemporaryDirectory(root, expected); !errors.Is(err, errSetupGitHubWebhookUnavailable) {
		t.Fatalf("replacement error=%v", err)
	}
	if _, err := os.Lstat(sentinel); err != nil {
		t.Fatalf("replacement content removed: %v", err)
	}
}
