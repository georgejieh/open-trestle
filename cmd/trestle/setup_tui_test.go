package main

import (
	"bytes"
	"context"
	setupcore "github.com/georgejieh/open-trestle/setup"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func initializedSetupTUIState(t *testing.T, root string) string {
	t.Helper()
	statePath := filepath.Join(root, "plan.json")
	plan, err := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTimeCLI())
	if err != nil {
		t.Fatal(err)
	}
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return statePath
}
func TestSetupTUIRendersProtectedStateOnce(t *testing.T) {
	root := t.TempDir()
	state := initializedSetupTUIState(t, root)
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", state, "--plain", "--once", "--width", "90"}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "OPEN TRESTLE SETUP") || !strings.Contains(stdout.String(), "state storage posture validated") {
		t.Fatalf("render=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
func TestSetupTUIRunsStorageAndObserverWithoutLeakingCredentials(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := initializedSetupTUIState(t, root)
	operator := "operator-" + strings.Repeat("a", 32)
	observer := "observer-" + strings.Repeat("b", 32)
	environment := func(name string) string {
		if name == "OPEN_TRESTLE_API_TOKEN" {
			return operator
		}
		if name == "OPEN_TRESTLE_OBSERVER_TOKEN" {
			return observer
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	input := strings.NewReader("x\nrun state_storage_posture_validated\nj\nj\nx\nrun observer_credential_posture_validated\nq\n")
	args := []string{"--state", state, "--storage-root", root, "--plain", "--width", "90"}
	code := runSetupTUIWithClock(args, input, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, environment)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run=(%d,%q)", code, stderr.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || plan.Revision() != 3 || len(plan.Receipts()) != 2 {
		t.Fatalf("plan=%d %v", plan.Revision(), err)
	}
	if strings.Contains(stdout.String(), operator) || strings.Contains(stdout.String(), observer) {
		t.Fatal("credential leaked")
	}
}
func TestSetupTUIRunsExactPolicyThenDryRun(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := initializedSetupTUIState(t, root)
	inventory, policy, inventoryID, runtimeID, reviewID := setupPolicyCLIPaths(t, root, "local")
	args := []string{"--state", state, "--route-inventory", inventory, "--runtime-policy", policy, "--approve-inventory-identity", inventoryID, "--approve-runtime-policy-identity", runtimeID, "--approve-review-policy-identity", reviewID, "--approved-by", "owner", "--plain", "--width", "100"}
	var stdout, stderr bytes.Buffer
	input := strings.NewReader(strings.Repeat("j\n", 4) + "x\nrun policy_validated\nj\nx\nrun dry_run_validated\nq\n")
	code := runSetupTUIWithClock(args, input, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, os.Getenv)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || plan.Revision() != 3 || len(plan.Receipts()) != 2 || plan.Receipts()[0].Key() != setupcore.CheckPolicyValidated || plan.Receipts()[1].Key() != setupcore.CheckDryRunValidated {
		t.Fatalf("plan=%d %#v %v", plan.Revision(), plan.Receipts(), err)
	}
	for _, forbidden := range []string{"127.0.0.1", "OPEN_TRESTLE_PROVIDER", "candidate_generation", "verdicts"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("leaked %s", forbidden)
		}
	}
}
func TestSetupTUIRejectsPartialPolicyConfigurationBeforeOpeningState(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing.json")
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", missing, "--route-inventory", "routes.json"}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("code=%d", code)
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts", missing + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}

func TestSetupTUIMissingStateAndInvalidWidthHaveNoFilesystemEffects(t *testing.T) {
	for _, test := range []struct {
		name  string
		width string
		want  int
	}{{"missing valid width", "90", 1}, {"missing invalid width", "1", 2}} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			missing := filepath.Join(root, "missing.json")
			var stdout, stderr bytes.Buffer
			code := runSetupTUIWithClock([]string{"--state", missing, "--plain", "--once", "--width", test.width}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
			if code != test.want || stdout.Len() != 0 {
				t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
			}
			for _, path := range []string{missing, missing + ".lock", missing + ".receipts", missing + ".next"} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("created %s", path)
				}
			}
		})
	}
}

func TestSetupTUIOnceDoesNotCreateWriterLock(t *testing.T) {
	root := t.TempDir()
	state := initializedSetupTUIState(t, root)
	lock := state + ".lock"
	if err := os.Remove(lock); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", state, "--plain", "--once", "--width", "90"}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d error=%q", code, stderr.String())
	}
	if _, err := os.Lstat(lock); !os.IsNotExist(err) {
		t.Fatal("one-shot render created writer lock")
	}
}

func TestSetupTUIRunsBackupThenAdministratorChecks(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := initializedSetupTUIState(t, root)
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	backupRoot := t.TempDir()
	_ = os.Chmod(backupRoot, 0o700)
	snapshot := filepath.Join(backupRoot, "plan.snapshot.json")
	if _, err = setupcore.CreateBackupSnapshot(context.Background(), state, snapshot, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"--state", state, "--backup-snapshot", snapshot, "--administrator-approved-by", "owner", "--plain", "--width", "90"}
	input := strings.NewReader("j\nx\nrun backup_validated\nx\nrun local_administrator_validated\nq\n")
	code := runSetupTUIWithClock(args, input, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, os.Getenv)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	got, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || got.Revision() != 3 || got.Receipts()[0].Key() != setupcore.CheckBackupValidated || got.Receipts()[1].Key() != setupcore.CheckLocalAdministratorValidated {
		t.Fatalf("plan=%d %#v %v", got.Revision(), got.Receipts(), err)
	}
	if strings.Contains(stdout.String(), snapshot) {
		t.Fatal("backup path leaked")
	}
}

func TestSetupTUIServiceRunsConfiguredLocalInferenceChecker(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	statePath := initializedSetupTUIState(t, root)
	inventory, policy, inventoryID, runtimeID, reviewID := setupPolicyCLIPaths(t, root, "local")
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: os.Getenv, inferenceFactory: failingSetupInferenceFactory{}, statePath: statePath, routeInventory: inventory, runtimePolicy: policy, inventoryIdentity: inventoryID, runtimePolicyIdentity: runtimeID, reviewPolicyIdentity: reviewID, approvedBy: "owner"}
	plan, err := service.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, receipt, err := service.RunCheck(context.Background(), setupcore.CheckPolicyValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed {
		t.Fatalf("policy=%v %s", err, receipt.State())
	}
	_, receipt, err = service.RunCheck(context.Background(), setupcore.CheckLocalInferenceValidated, plan.Identity())
	if err != nil || receipt.Key() != setupcore.CheckLocalInferenceValidated || receipt.State() != setupcore.CheckBlocked {
		t.Fatalf("inference=%v %s/%s", err, receipt.Key(), receipt.State())
	}
}

func TestSetupTUIRejectsPartialPostgresApprovalBeforeOpeningState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", missing, "--approve-postgres-authority-identity", strings.Repeat("a", 64)}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}

func TestSetupTUIServiceRunsRemoteProviderAuthorization(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileControlledHybrid)
	inventory, policy, inventoryID, runtimeID, reviewID := setupPolicyCLIPaths(t, root, "private_remote")
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(string) string { t.Fatal("credential environment read"); return "" }, statePath: statePath, routeInventory: inventory, runtimePolicy: policy, inventoryIdentity: inventoryID, runtimePolicyIdentity: runtimeID, reviewPolicyIdentity: reviewID, approvedBy: "owner"}
	plan, _ := service.Current(context.Background())
	_, receipt, err := service.RunCheck(context.Background(), setupcore.CheckRemoteProviderAuthorized, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed {
		t.Fatalf("receipt=%s err=%v", receipt.State(), err)
	}
}

func TestSetupTUIRejectsPartialReplicaReconciliationBeforeOpeningState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", missing, "--approve-replica-reconciliation-authority-identity", strings.Repeat("a", 64), "--replica-reconciliation-approved-by", "owner"}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}

func TestSetupTUIRejectsPartialSignedBundleBeforeOpeningState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	var stdout, stderr bytes.Buffer
	code := runSetupTUIWithClock([]string{"--state", missing, "--approve-signed-bundle-authority-identity", strings.Repeat("a", 64), "--signed-bundle-approved-by", "owner"}, strings.NewReader(""), &stdout, &stderr, fixedSetupClock{setupTimeCLI()}, os.Getenv)
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}
