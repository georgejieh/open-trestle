package main

import (
	"bytes"
	"context"
	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	setupcore "github.com/georgejieh/open-trestle/setup"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupSharedRateLimitProbeDefersDatabaseCredentialAndBindsPlan(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTimeCLI())
	reads, calls := 0, 0
	probe, authority, err := newSetupSharedRateLimitProbe(func(name string) string {
		reads++
		if name != "OPEN_TRESTLE_POSTGRES_URL" {
			t.Fatal(name)
		}
		return "postgres://private"
	}, plan, strings.Repeat("a", 64), func(_ context.Context, c setupSharedRateLimitConfiguration, value string) (string, error) {
		calls++
		if c.setupRootIdentity != plan.RootIdentity() || c.databaseAuthorityIdentity != strings.Repeat("a", 64) || value != "postgres://private" {
			t.Fatal("crossed configuration")
		}
		return strings.Repeat("b", 64), nil
	})
	if err != nil || probe.ConfigurationIdentity() == "" || probe.AuthorityIdentity() != authority {
		t.Fatalf("probe=%#v authority=%s err=%v", probe, authority, err)
	}
	if reads != 0 || calls != 0 {
		t.Fatal("constructor caused effect")
	}
	result := probe.Probe(context.Background())
	if result != setupcore.NewVerifiedSharedRateLimitProbeResult(authority, strings.Repeat("b", 64)) || reads != 1 || calls != 1 {
		t.Fatalf("result=%#v calls=%d/%d", result, reads, calls)
	}
	other, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-b", "owner", setupTimeCLI())
	_, changed, _ := newSetupSharedRateLimitProbe(func(string) string { return "" }, other, strings.Repeat("a", 64), func(context.Context, setupSharedRateLimitConfiguration, string) (string, error) { return "", nil })
	if changed == authority {
		t.Fatal("plan scope not bound")
	}
}
func TestSetupSharedRateLimitProbeSeparatesFailures(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTimeCLI())
	for _, test := range []struct {
		err  error
		want setupcore.CheckState
	}{{postgresstore.ErrDatabaseUnavailable, setupcore.CheckUnavailable}, {postgresstore.ErrSharedRateLimitConformanceUnavailable, setupcore.CheckUnavailable}, {postgresstore.ErrSharedRateLimitConformanceFailed, setupcore.CheckBlocked}} {
		probe, _, err := newSetupSharedRateLimitProbe(func(string) string { return "postgres://private" }, plan, strings.Repeat("a", 64), func(context.Context, setupSharedRateLimitConfiguration, string) (string, error) { return "", test.err })
		if err != nil {
			t.Fatal(err)
		}
		result := probe.Probe(context.Background())
		checkerPlan := plan
		_ = checkerPlan
		if test.want == setupcore.CheckUnavailable && result != setupcore.NewUnavailableSharedRateLimitProbeResult() {
			t.Fatalf("unavailable=%#v", result)
		}
		if test.want == setupcore.CheckBlocked && result != setupcore.NewInvalidSharedRateLimitProbeResult() {
			t.Fatalf("blocked=%#v", result)
		}
	}
}
func TestSetupSharedRateLimitProbeRejectsChangedAuthorityBeforeCredentialRead(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTimeCLI())
	reads, calls := 0, 0
	probe, authority, _ := newSetupSharedRateLimitProbe(func(string) string { reads++; return "postgres://private" }, plan, strings.Repeat("a", 64), func(context.Context, setupSharedRateLimitConfiguration, string) (string, error) {
		calls++
		return strings.Repeat("b", 64), nil
	})
	_ = authority
	probe.configuration.databaseAuthorityIdentity = strings.Repeat("c", 64)
	if result := probe.Probe(context.Background()); result != setupcore.NewInvalidSharedRateLimitProbeResult() || reads != 0 || calls != 0 {
		t.Fatalf("result=%#v calls=%d/%d", result, reads, calls)
	}
}

func TestSetupCLIRecordsSharedRateLimitReceiptAfterPostgresEvidence(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "kubernetes_ha", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", statePath}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	databaseAuthority := strings.Repeat("a", 64)
	postgresProbe := &setupPostgresFixtureProbe{identity: strings.Repeat("9", 64), authority: databaseAuthority}
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgresArgs := []string{"check", "postgres", "--state", statePath, "--approve-postgres-authority-identity", databaseAuthority, "--approved-by", "owner"}
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithDependencies(postgresArgs, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle); code != 0 {
		t.Fatalf("postgres=(%d,%s,%s)", code, stdout.String(), stderr.String())
	}
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.Current(context.Background())
	_ = state.Close()
	if err != nil {
		t.Fatal(err)
	}
	configuration := setupSharedRateLimitConfiguration{databaseAuthority, plan.RootIdentity()}
	authority, _ := deriveSetupSharedRateLimitAuthority(configuration)
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", "postgres://private")
	calls := 0
	executor := func(_ context.Context, got setupSharedRateLimitConfiguration, value string) (string, error) {
		calls++
		if got != configuration || value != "postgres://private" {
			t.Fatal("crossed shared limiter configuration")
		}
		return strings.Repeat("b", 64), nil
	}
	args := []string{"check", "rate-limit", "--state", statePath, "--approve-shared-rate-limit-authority-identity", authority, "--postgres-database-authority-identity", databaseAuthority, "--approved-by", "owner"}
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executor, executeSetupReplicaReconciliation, executeSetupSignedBundle)
	if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"shared_rate_limit_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}
func TestSetupCLIBlocksSharedRateLimitBeforePostgresReceipt(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "kubernetes_ha", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", statePath}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	state, _ := setupcore.OpenStateFile(statePath)
	plan, _ := state.Current(context.Background())
	_ = state.Close()
	databaseAuthority := strings.Repeat("a", 64)
	authority, _ := deriveSetupSharedRateLimitAuthority(setupSharedRateLimitConfiguration{databaseAuthority, plan.RootIdentity()})
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgresProbe := &setupPostgresFixtureProbe{identity: strings.Repeat("9", 64), authority: databaseAuthority}
	calls := 0
	executor := func(context.Context, setupSharedRateLimitConfiguration, string) (string, error) {
		calls++
		return strings.Repeat("b", 64), nil
	}
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithDependencies([]string{"check", "rate-limit", "--state", statePath, "--approve-shared-rate-limit-authority-identity", authority, "--postgres-database-authority-identity", databaseAuthority, "--approved-by", "owner"}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executor, executeSetupReplicaReconciliation, executeSetupSignedBundle)
	if code != 3 || calls != 0 || !strings.Contains(stdout.String(), `"state":"blocked"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}

func TestSetupTUIServiceRunsSharedRateLimitAfterPostgres(t *testing.T) {
	root := t.TempDir()
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileKubernetesHA)
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	plan, _ := state.Current(context.Background())
	databaseAuthority := strings.Repeat("a", 64)
	postgresProbe := &setupPostgresFixtureProbe{identity: strings.Repeat("9", 64), authority: databaseAuthority}
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(string) string { return "postgres://private" }, postgresProbe: postgresProbe, postgresAuthorityIdentity: databaseAuthority, postgresApprovedBy: "owner"}
	next, receipt, err := service.RunCheck(context.Background(), setupcore.CheckPostgresStorageValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed {
		t.Fatalf("postgres=%s err=%v", receipt.State(), err)
	}
	configuration := setupSharedRateLimitConfiguration{databaseAuthority, next.RootIdentity()}
	authority, _ := deriveSetupSharedRateLimitAuthority(configuration)
	calls := 0
	service.clock = fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}
	service.sharedRateLimitExecutor = func(context.Context, setupSharedRateLimitConfiguration, string) (string, error) {
		calls++
		return strings.Repeat("b", 64), nil
	}
	service.sharedRateLimitAuthorityIdentity = authority
	service.postgresDatabaseAuthorityIdentity = databaseAuthority
	service.sharedRateLimitApprovedBy = "owner"
	_, receipt, err = service.RunCheck(context.Background(), setupcore.CheckSharedRateLimitValidated, next.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
		t.Fatalf("rate=%s err=%v calls=%d", receipt.State(), err, calls)
	}
}
