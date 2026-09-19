package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestSetupReplicaReconciliationProbeDefersDatabaseCredentialAndBindsPlan(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTimeCLI())
	reads, calls := 0, 0
	probe, authority, err := newSetupReplicaReconciliationProbe(func(name string) string {
		reads++
		if name != "OPEN_TRESTLE_POSTGRES_URL" {
			t.Fatal(name)
		}
		return "postgres://private"
	}, plan, strings.Repeat("a", 64), func(_ context.Context, configuration setupReplicaReconciliationConfiguration, value string) (string, error) {
		calls++
		if configuration.setupRootIdentity != plan.RootIdentity() || configuration.databaseAuthorityIdentity != strings.Repeat("a", 64) || value != "postgres://private" {
			t.Fatal("crossed configuration")
		}
		return strings.Repeat("b", 64), nil
	})
	if err != nil || probe.ConfigurationIdentity() == "" || probe.AuthorityIdentity() != authority || reads != 0 || calls != 0 {
		t.Fatalf("probe=%#v authority=%s err=%v calls=%d/%d", probe, authority, err, reads, calls)
	}
	result := probe.Probe(context.Background())
	if result != setupcore.NewVerifiedReplicaReconciliationProbeResult(authority, strings.Repeat("b", 64)) || reads != 1 || calls != 1 {
		t.Fatalf("result=%#v calls=%d/%d", result, reads, calls)
	}
	other, _ := setupcore.NewPlan(setupcore.ProfileKubernetesHA, "tenant-a", "repo-b", "owner", setupTimeCLI())
	_, changed, _ := newSetupReplicaReconciliationProbe(func(string) string { return "" }, other, strings.Repeat("a", 64), func(context.Context, setupReplicaReconciliationConfiguration, string) (string, error) { return "", nil })
	if changed == authority {
		t.Fatal("plan scope not bound")
	}
	probe.configuration.databaseAuthorityIdentity = strings.Repeat("c", 64)
	if changedResult := probe.Probe(context.Background()); changedResult != setupcore.NewInvalidReplicaReconciliationProbeResult() || reads != 1 || calls != 1 {
		t.Fatalf("changed=%#v calls=%d/%d", changedResult, reads, calls)
	}
}

func TestSetupCLIRecordsReplicaReconciliationReceiptAfterPostgresEvidence(t *testing.T) {
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
	configuration := setupReplicaReconciliationConfiguration{databaseAuthority, plan.RootIdentity()}
	authority, _ := deriveSetupReplicaReconciliationAuthority(configuration)
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", "postgres://private")
	calls := 0
	executor := func(_ context.Context, got setupReplicaReconciliationConfiguration, value string) (string, error) {
		calls++
		if got != configuration || value != "postgres://private" {
			t.Fatal("crossed replica reconciliation configuration")
		}
		return strings.Repeat("b", 64), nil
	}
	args := []string{"check", "reconciliation", "--state", statePath, "--approve-replica-reconciliation-authority-identity", authority, "--postgres-database-authority-identity", databaseAuthority, "--approved-by", "owner"}
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executor, executeSetupSignedBundle)
	if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"replica_reconciliation_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}

func TestSetupTUIServiceRunsReplicaReconciliationAfterPostgres(t *testing.T) {
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
	configuration := setupReplicaReconciliationConfiguration{databaseAuthority, next.RootIdentity()}
	authority, _ := deriveSetupReplicaReconciliationAuthority(configuration)
	calls := 0
	service.clock = fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}
	service.replicaReconciliationExecutor = func(context.Context, setupReplicaReconciliationConfiguration, string) (string, error) {
		calls++
		return strings.Repeat("b", 64), nil
	}
	service.replicaReconciliationAuthorityIdentity = authority
	service.postgresDatabaseAuthorityIdentity = databaseAuthority
	service.replicaReconciliationApprovedBy = "owner"
	_, receipt, err = service.RunCheck(context.Background(), setupcore.CheckReplicaReconciliationValidated, next.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
		t.Fatalf("reconciliation=%s err=%v calls=%d", receipt.State(), err, calls)
	}
}

func TestSetupCLIBlocksReplicaReconciliationBeforePostgresReceipt(t *testing.T) {
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
	authority, _ := deriveSetupReplicaReconciliationAuthority(setupReplicaReconciliationConfiguration{databaseAuthority, plan.RootIdentity()})
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgresProbe := &setupPostgresFixtureProbe{identity: strings.Repeat("9", 64), authority: databaseAuthority}
	calls := 0
	executor := func(context.Context, setupReplicaReconciliationConfiguration, string) (string, error) {
		calls++
		return strings.Repeat("b", 64), nil
	}
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithDependencies([]string{"check", "reconciliation", "--state", statePath, "--approve-replica-reconciliation-authority-identity", authority, "--postgres-database-authority-identity", databaseAuthority, "--approved-by", "owner"}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executor, executeSetupSignedBundle)
	if code != 3 || calls != 0 || !strings.Contains(stdout.String(), `"state":"blocked"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}
