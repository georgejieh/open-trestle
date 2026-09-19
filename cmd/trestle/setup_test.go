package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type failingSetupInferenceFactory struct{}

func (failingSetupInferenceFactory) FactoryIdentity() string { return strings.Repeat("9", 64) }
func (failingSetupInferenceFactory) Build(context.Context, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error) {
	return gateway.RouteDispatcherCatalog{}, errors.New("not connected")
}

type fixedSetupClock struct{ at time.Time }

func (c fixedSetupClock) Now() time.Time { return c.at }
func TestSetupInitAndInspectUseProtectedResumableState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "setup.json")
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "platform-owner", "--state", state}
	code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"created"`) {
		t.Fatalf("init=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	info, err := os.Stat(state)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
	encoded, err := os.ReadFile(state)
	plan, decodeErr := setupcore.DecodePlan(encoded)
	if err != nil || decodeErr != nil || plan.Ready() || plan.Profile() != setupcore.ProfileLocalSingleNode {
		t.Fatalf("plan=%#v read=%v decode=%v", plan, err, decodeErr)
	}
	stdout.Reset()
	stderr.Reset()
	if code = runSetupWithClock([]string{"inspect", "--state", state}, &stdout, &stderr, fixedSetupClock{}); code != 0 || stderr.Len() != 0 {
		t.Fatalf("inspect=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code = runSetupWithClock([]string{"inspect", "--state", state, "--expected-root-identity", strings.Repeat("f", 64)}, &stdout, &stderr, fixedSetupClock{}); code != 1 || stdout.Len() != 0 {
		t.Fatalf("wrong root=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code = runSetupWithClock([]string{"inspect", "--state", state, "--expected-root-identity", plan.RootIdentity()}, &stdout, &stderr, fixedSetupClock{}); code != 0 {
		t.Fatalf("expected root=%d %s", code, stderr.String())
	}
	inspected, err := setupcore.DecodePlan(bytes.TrimSpace(stdout.Bytes()))
	if err != nil || inspected.Identity() != plan.Identity() {
		t.Fatalf("inspected=%v", err)
	}
}
func TestSetupInitRefusesOverwriteAndUnsafeInput(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "setup.json")
	if err := os.WriteFile(state, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 1 || stdout.Len() != 0 || stderr.String() != "setup initialization failed\n" {
		t.Fatalf("overwrite=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if stringMustRead(t, state) != "existing" {
		t.Fatal("existing state changed")
	}
	stdout.Reset()
	stderr.Reset()
	args[2] = "unknown"
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 2 {
		t.Fatalf("profile=%d", code)
	}
}
func TestSetupInspectRejectsBroadPermissionsAndSymlink(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "setup.json")
	plan, _ := setupcore.NewPlan(setupcore.ProfileAirGapped, "tenant-a", "repo-a", "owner", setupTimeCLI())
	encoded, _ := setupcore.EncodePlan(plan)
	if err := os.WriteFile(state, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"inspect", "--state", state}, &stdout, &stderr, fixedSetupClock{}); code != 1 || stdout.Len() != 0 {
		t.Fatalf("broad=%d", code)
	}
	_ = os.Chmod(state, 0o600)
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runSetupWithClock([]string{"inspect", "--state", link}, &stdout, &stderr, fixedSetupClock{}); code != 1 {
		t.Fatalf("link=%d", code)
	}
}
func setupTimeCLI() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
func stringMustRead(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func TestSetupInitRejectsSymlinkedOrWritableParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	args := []string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", filepath.Join(link, "setup.json")}
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 1 {
		t.Fatalf("symlink parent=%d", code)
	}
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(writable, 0o777)
	args[len(args)-1] = filepath.Join(writable, "setup.json")
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 1 {
		t.Fatalf("writable parent=%d", code)
	}
}

func TestSetupInspectHasNoFilesystemSideEffects(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"inspect", "--state", missing}, &stdout, &stderr, fixedSetupClock{}); code != 1 {
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
	if code := runSetupWithClock([]string{"inspect", "--state", corrupt}, &stdout, &stderr, fixedSetupClock{}); code != 1 {
		t.Fatalf("corrupt=%d", code)
	}
	for _, path := range []string{corrupt + ".lock", corrupt + ".receipts", corrupt + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s: %v", path, err)
		}
	}
}

func TestSetupStorageAndObserverChecksAdvanceOnlyThroughRunner(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	init := []string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}
	if code := runSetupWithClock(init, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	storage := filepath.Join(root, "storage")
	_ = os.Mkdir(storage, 0o700)
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"check", "storage", "--state", state, "--storage-root", storage}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}); code != 0 || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("storage=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "operator-"+strings.Repeat("a", 32))
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "observer-"+strings.Repeat("b", 32))
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"check", "observer", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}); code != 0 || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("observer=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || plan.Revision() != 3 || len(plan.Receipts()) != 2 {
		t.Fatalf("plan=%v revision=%d", err, plan.Revision())
	}
	encoded, _ := setupcore.EncodePlan(plan)
	if strings.Contains(string(encoded), os.Getenv("OPEN_TRESTLE_API_TOKEN")) || strings.Contains(string(encoded), os.Getenv("OPEN_TRESTLE_OBSERVER_TOKEN")) {
		t.Fatal("credential persisted")
	}
}
func TestSetupBlockedCheckReturnsClosedNonzeroOutcome(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	_ = runSetupWithClock([]string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	unsafe := filepath.Join(root, "unsafe")
	_ = os.Mkdir(unsafe, 0o755)
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithClock([]string{"check", "storage", "--state", state, "--storage-root", unsafe}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)})
	if code != 3 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"state":"blocked"`) || !strings.Contains(stdout.String(), `"recovery_action":"configure_dependency"`) {
		t.Fatalf("blocked=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func setupPolicyCLIPaths(t *testing.T, root, zone string) (string, string, string, string, string) {
	t.Helper()
	endpoints := []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"}
	if zone != "local" {
		endpoints = []string{"https://one.example/v1", "https://two.example/v1"}
	}
	routes := make([]map[string]any, 2)
	connections := make([]map[string]any, 2)
	for i := range routes {
		suffix := string(rune('a' + i))
		routes[i] = map[string]any{"zone": zone, "provider_id": "provider-" + suffix, "adapter_id": "adapter-" + suffix, "connection_id": "connection-" + suffix, "model_id": "model-" + suffix, "model_version": "v1", "max_context_tokens": 64000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 0, "output_micro_usd_per_million_tokens": 0, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"approved":true}`)), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0}
		connections[i] = map[string]any{"implementation": "openai_responses", "adapter_id": "adapter-" + suffix, "endpoint": endpoints[i], "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_" + strings.ToUpper(suffix)}
	}
	inventoryDocument, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryDocument))
	if err != nil {
		t.Fatal(err)
	}
	policyDocument, _ := json.Marshal(map[string]any{"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("a", 64), "min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{zone}, "content_logging_allowed": false, "estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0, "pinned_route_record_identity": "", "preferred_route_record_identities": []string{}, "verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true, "connections": connections})
	inventoryPath, policyPath := filepath.Join(root, "routes.json"), filepath.Join(root, "policy.json")
	if os.WriteFile(inventoryPath, inventoryDocument, 0o600) != nil || os.WriteFile(policyPath, policyDocument, 0o600) != nil {
		t.Fatal("write policy fixture")
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyDocument), inventory)
	if err != nil {
		t.Fatal(err)
	}
	return inventoryPath, policyPath, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity()
}
func TestSetupPolicyCheckIsOfflineAndReceiptDriven(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	inventory, policy, inventoryID, runtimePolicyID, reviewPolicyID := setupPolicyCLIPaths(t, root, "local")
	stdout.Reset()
	stderr.Reset()
	args := []string{"check", "policy", "--state", state, "--route-inventory", inventory, "--runtime-policy", policy, "--approve-inventory-identity", inventoryID, "--approve-runtime-policy-identity", runtimePolicyID, "--approve-review-policy-identity", reviewPolicyID, "--approved-by", "owner"}
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"key":"policy_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("policy=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	args[1] = "dry-run"
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"key":"dry_run_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("dry run=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	args[1] = "inference"
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClockAndInference(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(3 * time.Second)}, failingSetupInferenceFactory{}); code != 3 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"key":"local_inference_validated"`) || !strings.Contains(stdout.String(), `"state":"blocked"`) {
		t.Fatalf("inference=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || plan.Revision() != 4 || len(plan.Receipts()) != 3 {
		t.Fatalf("plan=%d %v", plan.Revision(), err)
	}
	encoded, _ := setupcore.EncodePlan(plan)
	if bytes.Contains(encoded, []byte("127.0.0.1")) || bytes.Contains(encoded, []byte("OPEN_TRESTLE_PROVIDER")) {
		t.Fatal("policy details persisted")
	}
}
func TestSetupPolicyCheckPersistsUnavailableOutcome(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	_ = runSetupWithClock([]string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	stdout.Reset()
	stderr.Reset()
	fixtureRoot := filepath.Join(root, "fixture")
	_ = os.Mkdir(fixtureRoot, 0o700)
	_, _, inventoryID, runtimePolicyID, reviewPolicyID := setupPolicyCLIPaths(t, fixtureRoot, "local")
	code := runSetupWithClock([]string{"check", "policy", "--state", state, "--route-inventory", filepath.Join(root, "missing-routes"), "--runtime-policy", filepath.Join(root, "missing-policy"), "--approve-inventory-identity", inventoryID, "--approve-runtime-policy-identity", runtimePolicyID, "--approve-review-policy-identity", reviewPolicyID, "--approved-by", "owner"}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)})
	if code != 3 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"state":"unavailable"`) || !strings.Contains(stdout.String(), `"recovery_action":"correct_policy"`) {
		t.Fatalf("unavailable=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func TestSetupPolicyUsageErrorDoesNotOpenState(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing-plan.json")
	var stdout, stderr bytes.Buffer
	code := runSetupWithClock([]string{"check", "policy", "--state", missing}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("usage=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts", missing + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
}

func TestSetupPolicyCheckRejectsMismatchedApprovalAndActor(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	_ = runSetupWithClock([]string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	inventory, policy, inventoryID, runtimeID, reviewID := setupPolicyCLIPaths(t, root, "local")
	args := []string{"check", "policy", "--state", state, "--route-inventory", inventory, "--runtime-policy", policy, "--approve-inventory-identity", inventoryID, "--approve-runtime-policy-identity", strings.Repeat("b", 64), "--approve-review-policy-identity", reviewID, "--approved-by", "owner"}
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}); code != 3 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"state":"blocked"`) {
		t.Fatalf("mismatch=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || plan.Revision() != 2 {
		t.Fatalf("blocked receipt=%d %v", plan.Revision(), err)
	}
	args[11] = runtimeID
	args[15] = "other"
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}); code != 1 || stdout.Len() != 0 || stderr.String() != "setup check failed\n" {
		t.Fatalf("actor=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	again, _ := setupcore.InspectStateFile(context.Background(), state)
	if again.Revision() != 2 {
		t.Fatal("unauthorized actor changed state")
	}
}

func TestSetupCreatesAndValidatesOfflineAuthorityAndBackup(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state", "plan.json")
	if err := os.Mkdir(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	init := []string{"init", "--profile", "local_single_node", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}
	if code := runSetupWithClock(init, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatalf("init=%d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"check", "administrator", "--state", state, "--approved-by", "owner"}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}); code != 0 || !strings.Contains(stdout.String(), `"key":"local_administrator_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("admin=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	current, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	backupRoot := filepath.Join(root, "backup")
	if err = os.Mkdir(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(backupRoot, "plan.snapshot.json")
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"backup", "create", "--state", state, "--destination", snapshot, "--expected-plan-identity", current.Identity()}, &stdout, &stderr, fixedSetupClock{}); code != 0 || !strings.Contains(stdout.String(), `"status":"backup_created"`) || !strings.Contains(stdout.String(), current.Identity()) {
		t.Fatalf("backup=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"check", "backup", "--state", state, "--backup-snapshot", snapshot}, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(2 * time.Second)}); code != 0 || !strings.Contains(stdout.String(), `"key":"backup_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("check=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	restoreRoot := filepath.Join(root, "restore")
	if err = os.Mkdir(restoreRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(restoreRoot, "plan.json")
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"backup", "restore", "--snapshot", snapshot, "--destination", restoredPath, "--expected-root-identity", current.RootIdentity(), "--expected-plan-identity", current.Identity()}, &stdout, &stderr, fixedSetupClock{}); code != 0 || !strings.Contains(stdout.String(), `"status":"backup_restored"`) {
		t.Fatalf("restore=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	restored, err := setupcore.InspectStateFile(context.Background(), restoredPath)
	if err != nil || restored.Identity() != current.Identity() {
		t.Fatalf("restored=%s err=%v", restored.Identity(), err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock([]string{"backup", "create", "--state", state, "--destination", snapshot, "--expected-plan-identity", current.Identity()}, &stdout, &stderr, fixedSetupClock{}); code != 1 || stdout.Len() != 0 || stderr.String() != "setup backup failed\n" {
		t.Fatalf("duplicate=%d out=%s err=%q", code, stdout.String(), stderr.String())
	}
}

func TestSetupOfflineCheckArgumentsFailClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cases := [][]string{{"check", "administrator", "--state", "plan.json"}, {"check", "administrator", "--state", "plan.json", "--approved-by", "owner", "--storage-root", "x"}, {"check", "administrator", "--state", "plan.json", "--approved-by", "bad owner"}, {"check", "backup", "--state", "plan.json"}, {"check", "backup", "--state", "plan.json", "--backup-snapshot", "x", "--approved-by", "owner"}, {"backup", "create", "--state", "a", "--destination", "b"}, {"backup", "restore", "--snapshot", "a", "--destination", "b"}, {"check", "inference", "--state", "plan.json"}, {"check", "postgres", "--state", "plan.json"}, {"check", "postgres", "--state", "plan.json", "--approve-postgres-authority-identity", strings.Repeat("a", 64), "--approved-by", "owner", "--storage-root", "x"}}
	for _, args := range cases {
		stdout.Reset()
		stderr.Reset()
		if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{}); code != 2 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}

func TestSetupRemoteProviderAuthorizationIsOfflineAndReceiptDriven(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	inventory, policy, inventoryID, runtimePolicyID, reviewPolicyID := setupPolicyCLIPaths(t, root, "private_remote")
	stdout.Reset()
	stderr.Reset()
	args := []string{"check", "provider", "--state", state, "--route-inventory", inventory, "--runtime-policy", policy, "--approve-inventory-identity", inventoryID, "--approve-runtime-policy-identity", runtimePolicyID, "--approve-review-policy-identity", reviewPolicyID, "--approved-by", "owner"}
	if code := runSetupWithClock(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"key":"remote_provider_authorized"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("provider=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	encoded, _ := os.ReadFile(state)
	if bytes.Contains(encoded, []byte("one.example")) || bytes.Contains(encoded, []byte("OPEN_TRESTLE_PROVIDER")) {
		t.Fatal("provider configuration persisted")
	}
}
