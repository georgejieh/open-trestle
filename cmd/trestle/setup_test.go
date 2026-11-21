package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

type fixedSetupClock struct{ at time.Time }

func (c fixedSetupClock) Now() time.Time { return c.at }

func setupTimeCLI() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }

func stringMustRead(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

// initializeSetupStateCLI writes a new protected local plan at state.
func initializeSetupStateCLI(t *testing.T, state string) setupcore.Plan {
	t.Helper()
	plan, err := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTimeCLI())
	if err != nil {
		t.Fatal(err)
	}
	store, err := setupcore.OpenStateFile(state)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestSetupInspectUsesProtectedState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "setup.json")
	plan := initializeSetupStateCLI(t, state)
	var stdout, stderr bytes.Buffer
	if code := runSetup([]string{"inspect", "--state", state}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("inspect=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetup([]string{"inspect", "--state", state, "--expected-root-identity", strings.Repeat("f", 64)}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("wrong root=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetup([]string{"inspect", "--state", state, "--expected-root-identity", plan.RootIdentity()}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected root=%d %s", code, stderr.String())
	}
	inspected, err := setupcore.DecodePlan(bytes.TrimSpace(stdout.Bytes()))
	if err != nil || inspected.Identity() != plan.Identity() {
		t.Fatalf("inspected=%v", err)
	}
}

func TestSetupInspectRejectsBroadPermissionsAndSymlink(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "setup.json")
	plan, _ := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTimeCLI())
	encoded, _ := setupcore.EncodePlan(plan)
	if err := os.WriteFile(state, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runSetup([]string{"inspect", "--state", state}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("broad=%d", code)
	}
	_ = os.Chmod(state, 0o600)
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runSetup([]string{"inspect", "--state", link}, &stdout, &stderr); code != 1 {
		t.Fatalf("link=%d", code)
	}
}

func TestSetupInspectHasNoFilesystemSideEffects(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing.json")
	var stdout, stderr bytes.Buffer
	if code := runSetup([]string{"inspect", "--state", missing}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing=%d", code)
	}
	for _, path := range []string{missing + ".lock", missing + ".receipts", missing + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s: %v", path, err)
		}
	}
	corrupt := filepath.Join(root, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetup([]string{"inspect", "--state", corrupt}, &stdout, &stderr); code != 1 {
		t.Fatalf("corrupt=%d", code)
	}
	for _, path := range []string{corrupt + ".lock", corrupt + ".receipts", corrupt + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s: %v", path, err)
		}
	}
}

func TestSetupBackupCreatesAndRestoresProtectedSnapshot(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state", "plan.json")
	if err := os.Mkdir(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	current := initializeSetupStateCLI(t, state)
	backupRoot := filepath.Join(root, "backup")
	if err := os.Mkdir(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(backupRoot, "plan.snapshot.json")
	var stdout, stderr bytes.Buffer
	if code := runSetup([]string{"backup", "create", "--state", state, "--destination", snapshot, "--expected-plan-identity", current.Identity()}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"status":"backup_created"`) || !strings.Contains(stdout.String(), current.Identity()) {
		t.Fatalf("backup=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	restoreRoot := filepath.Join(root, "restore")
	if err := os.Mkdir(restoreRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(restoreRoot, "plan.json")
	stdout.Reset()
	stderr.Reset()
	if code := runSetup([]string{"backup", "restore", "--snapshot", snapshot, "--destination", restoredPath, "--expected-root-identity", current.RootIdentity(), "--expected-plan-identity", current.Identity()}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"status":"backup_restored"`) {
		t.Fatalf("restore=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	restored, err := setupcore.InspectStateFile(context.Background(), restoredPath)
	if err != nil || restored.Identity() != current.Identity() {
		t.Fatalf("restored=%s err=%v", restored.Identity(), err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetup([]string{"backup", "create", "--state", state, "--destination", snapshot, "--expected-plan-identity", current.Identity()}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "setup backup failed\n" {
		t.Fatalf("duplicate=%d out=%s err=%q", code, stdout.String(), stderr.String())
	}
}

func TestSetupArgumentsFailClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cases := [][]string{{}, {"init", "--state", "plan.json"}, {"check", "storage", "--state", "plan.json"}, {"inspect"}, {"inspect", "--state", "plan.json", "--expected-root-identity", "short"}, {"backup"}, {"backup", "create", "--state", "a", "--destination", "b"}, {"backup", "restore", "--snapshot", "a", "--destination", "b"}}
	for _, args := range cases {
		stdout.Reset()
		stderr.Reset()
		if code := runSetup(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}
