package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestSetupPostgresProbeDefersAndRedactsDSN(t *testing.T) {
	secret := "postgres://runtime:secret@database/trestle"
	reads, calls := 0, 0
	authority := strings.Repeat("a", 64)
	probe, err := newSetupPostgresStorageProbe(func(name string) string {
		reads++
		if name != "OPEN_TRESTLE_POSTGRES_URL" {
			t.Fatalf("name=%s", name)
		}
		return secret
	}, func(_ context.Context, dsn string) (string, error) {
		calls++
		if dsn != secret {
			t.Fatal("dsn mismatch")
		}
		return authority, nil
	})
	if err != nil || reads != 0 || calls != 0 {
		t.Fatalf("new=%v reads=%d calls=%d", err, reads, calls)
	}
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	checker, err := setupcore.NewPostgresStorageChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckPassed || reads != 1 || calls != 1 {
		t.Fatalf("result=%s reads=%d calls=%d", result.State(), reads, calls)
	}
	if strings.Contains(fmt.Sprintf("%#v", probe), secret) {
		t.Fatal("probe leaked DSN")
	}
}
func TestSetupPostgresProbeClassifiesDatabaseOutcomes(t *testing.T) {
	authority := strings.Repeat("a", 64)
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	for _, test := range []struct {
		err  error
		want setupcore.CheckState
	}{{postgresstore.ErrDatabaseUnavailable, setupcore.CheckUnavailable}, {postgresstore.ErrMigrationConflict, setupcore.CheckBlocked}, {postgresstore.ErrDatabaseAuthorityMismatch, setupcore.CheckBlocked}} {
		probe, _ := newSetupPostgresStorageProbe(func(string) string { return "postgres://secret" }, func(context.Context, string) (string, error) { return "", test.err })
		checker, _ := setupcore.NewPostgresStorageChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("%v=%s", test.err, result.State())
		}
	}
	var typedNil setupPostgresExecutor
	if probe, err := newSetupPostgresStorageProbe(func(string) string { return "" }, typedNil); err == nil || probe != nil {
		t.Fatalf("nil=%#v %v", probe, err)
	}
}

type setupPostgresFixtureProbe struct {
	identity, authority string
	calls               int
}

func (p *setupPostgresFixtureProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupPostgresFixtureProbe) Probe(context.Context) setupcore.PostgresStorageProbeResult {
	p.calls++
	return setupcore.NewVerifiedPostgresStorageProbeResult(p.authority)
}
func TestSetupCLIRecordsExactPostgresStorageReceipt(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	authority := strings.Repeat("a", 64)
	probe := &setupPostgresFixtureProbe{identity: strings.Repeat("b", 64), authority: authority}
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	stdout.Reset()
	stderr.Reset()
	args := []string{"check", "postgres", "--state", state, "--approve-postgres-authority-identity", authority, "--approved-by", "owner"}
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, probe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle)
	if code != 0 || stderr.Len() != 0 || probe.calls != 1 || !strings.Contains(stdout.String(), `"key":"postgres_storage_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), probe.calls)
	}
}

func TestSetupTUIServiceRunsPostgresStorageChecker(t *testing.T) {
	root := t.TempDir()
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileControlledHybrid)
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	authority := strings.Repeat("a", 64)
	probe := &setupPostgresFixtureProbe{identity: strings.Repeat("b", 64), authority: authority}
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(string) string { return "" }, statePath: statePath, postgresProbe: probe, postgresAuthorityIdentity: authority, postgresApprovedBy: "owner"}
	plan, _ := service.Current(context.Background())
	_, receipt, err := service.RunCheck(context.Background(), setupcore.CheckPostgresStorageValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || probe.calls != 1 {
		t.Fatalf("result=%v %s calls=%d", err, receipt.State(), probe.calls)
	}
}
func initializedSetupTUIStateForProfile(t *testing.T, root string, profile setupcore.Profile) string {
	t.Helper()
	path := filepath.Join(root, "profile-plan.json")
	plan, err := setupcore.NewPlan(profile, "tenant-a", "repo-a", "owner", setupTimeCLI())
	if err != nil {
		t.Fatal(err)
	}
	state, err := setupcore.OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	return path
}
