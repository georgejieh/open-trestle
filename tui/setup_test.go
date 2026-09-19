package tui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupFixtureClock struct{ at time.Time }

func (c setupFixtureClock) Now() time.Time { return c.at }

type setupFixtureChecker struct {
	key      setupcore.CheckKey
	identity string
}

func (c setupFixtureChecker) Key() setupcore.CheckKey { return c.key }
func (c setupFixtureChecker) CheckerIdentity() string { return c.identity }
func (c setupFixtureChecker) Check(context.Context, setupcore.Plan) setupcore.CheckResult {
	return setupcore.NewPassedCheckResult(strings.Repeat("a", 64))
}

type setupFixtureService struct {
	state  *setupcore.StateFile
	runner *setupcore.Runner
}

func (s setupFixtureService) Current(ctx context.Context) (setupcore.Plan, error) {
	return s.state.Current(ctx)
}
func (s setupFixtureService) RunCheck(ctx context.Context, key setupcore.CheckKey, expectedPlanIdentity string) (setupcore.Plan, setupcore.CheckReceipt, error) {
	plan, receipt, err := s.runner.RunExpected(ctx, key, expectedPlanIdentity)
	if errors.Is(err, setupcore.ErrCheckNotAuthorized) {
		err = ErrSetupCheckUnavailable
	}
	return plan, receipt, err
}
func setupInterfaceFixture(t *testing.T, input string) (*SetupInterface, *bytes.Buffer, *setupcore.StateFile) {
	t.Helper()
	root := t.TempDir()
	state, err := setupcore.OpenStateFile(root + "/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", time.UnixMilli(100).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	var identity string
	for _, authority := range plan.CheckerAuthorities() {
		if authority.Key == setupcore.CheckStateStoragePostureValidated {
			identity = authority.CheckerIdentity
		}
	}
	runner, err := setupcore.NewRunner(state, []setupcore.Checker{setupFixtureChecker{setupcore.CheckStateStoragePostureValidated, identity}}, setupFixtureClock{time.UnixMilli(200).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	output := &bytes.Buffer{}
	interface_, err := NewSetup(setupFixtureService{state, runner}, strings.NewReader(input), output, SetupOptions{Width: 90, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	return interface_, output, state
}
func TestSetupInterfaceRunsSelectedCheckAndShowsReplayState(t *testing.T) {
	interface_, output, state := setupInterfaceFixture(t, "x\nrun state_storage_posture_validated\nq\n")
	defer state.Close()
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, err := state.Current(context.Background())
	if err != nil || plan.Revision() != 2 || len(plan.Receipts()) != 1 {
		t.Fatalf("plan=%d %v", plan.Revision(), err)
	}
	rendered := output.String()
	for _, want := range []string{"OPEN TRESTLE SETUP", "local single node", "state storage posture validated", "passed", "Receipt history", "Commands: j next"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in %q", want, rendered)
		}
	}
}
func TestSetupInterfaceNavigationAndUnavailableCheckStayTruthful(t *testing.T) {
	interface_, output, state := setupInterfaceFixture(t, "j\nx\nrun backup_validated\nq\n")
	defer state.Close()
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, _ := state.Current(context.Background())
	if plan.Revision() != 1 {
		t.Fatal("unsupported check advanced plan")
	}
	if !strings.Contains(output.String(), "No checker is configured for this requirement") || !strings.Contains(output.String(), "backup validated") {
		t.Fatal(output.String())
	}
}
func TestSetupInterfaceRejectsInvalidConstructionAndOversizedInput(t *testing.T) {
	if interface_, err := NewSetup(nil, strings.NewReader(""), &bytes.Buffer{}, SetupOptions{}); err == nil || interface_ != nil {
		t.Fatal("nil service accepted")
	}
	interface_, _, state := setupInterfaceFixture(t, strings.Repeat("x", maxCommandBytes+1)+"\n")
	defer state.Close()
	if err := interface_.Run(context.Background()); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("err=%v", err)
	}
}

func TestSetupInterfaceRequiresExactConfirmation(t *testing.T) {
	interface_, _, state := setupInterfaceFixture(t, "x\nq\n")
	defer state.Close()
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, _ := state.Current(context.Background())
	if plan.Revision() != 1 || len(plan.Receipts()) != 0 {
		t.Fatal("unconfirmed check changed state")
	}
}
func TestSetupRendererHonorsMinimumWidth(t *testing.T) {
	interface_, output, state := setupInterfaceFixture(t, "")
	defer state.Close()
	interface_.options.Width = 60
	interface_.options.Once = true
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if width := utf8.RuneCountInString(line); width > 60 {
			t.Fatalf("line width %d: %q", width, line)
		}
	}
}

func TestSetupRequirementActionDescribesOfflineCheckConfiguration(t *testing.T) {
	plan, err := setupcore.NewPlan(setupcore.ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	want := map[setupcore.CheckKey]string{setupcore.CheckBackupValidated: "--backup-snapshot", setupcore.CheckLocalAdministratorValidated: "--administrator-approved-by", setupcore.CheckLocalInferenceValidated: "explicit local model probe"}
	for _, requirement := range plan.Requirements() {
		expected, ok := want[requirement.Key()]
		if !ok {
			continue
		}
		action := setupRequirementAction(requirement)
		if !strings.Contains(action, expected) || strings.Contains(action, "No built-in") {
			t.Fatalf("%s: %s", requirement.Key(), action)
		}
	}
}

func TestSetupRequirementActionDescribesPostgresAuthority(t *testing.T) {
	plan, err := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range plan.Requirements() {
		if requirement.Key() == setupcore.CheckPostgresStorageValidated {
			action := setupRequirementAction(requirement)
			if !strings.Contains(action, "admin postgres identity") || strings.Contains(action, "No built-in") {
				t.Fatalf("action=%s", action)
			}
			return
		}
	}
	t.Fatal("missing PostgreSQL requirement")
}

func TestSecretBackendSetupActionStaysDistinctFromEnvelopeStorage(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.UnixMilli(1).UTC())
	var requirement setupcore.Requirement
	for _, candidate := range plan.Requirements() {
		if candidate.Key() == setupcore.CheckSecretBackendValidated {
			requirement = candidate
			break
		}
	}
	action := setupRequirementAction(requirement)
	if !strings.Contains(action, "admin kms identity") || strings.Contains(strings.ToLower(action), "s3") {
		t.Fatalf("action=%q", action)
	}
}

func TestEnvelopeStorageSetupActionNamesEffectfulBoundary(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.UnixMilli(1).UTC())
	var requirement setupcore.Requirement
	for _, candidate := range plan.Requirements() {
		if candidate.Key() == setupcore.CheckEnvelopeStorageValidated {
			requirement = candidate
			break
		}
	}
	action := setupRequirementAction(requirement)
	if !strings.Contains(action, "admin envelope identity") || !strings.Contains(action, "exact delete") {
		t.Fatalf("action=%q", action)
	}
}

func TestRemoteProviderSetupActionStaysCredentialFree(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.UnixMilli(1).UTC())
	var requirement setupcore.Requirement
	for _, candidate := range plan.Requirements() {
		if candidate.Key() == setupcore.CheckRemoteProviderAuthorized {
			requirement = candidate
			break
		}
	}
	action := setupRequirementAction(requirement)
	if !strings.Contains(action, "credential-free") || !strings.Contains(action, "remote-provider authorization") {
		t.Fatalf("action=%q", action)
	}
}

func TestIntegrationPermissionSetupActionStaysReadOnly(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.UnixMilli(1).UTC())
	var requirement setupcore.Requirement
	for _, candidate := range plan.Requirements() {
		if candidate.Key() == setupcore.CheckIntegrationPermissionsValidated {
			requirement = candidate
			break
		}
	}
	action := setupRequirementAction(requirement)
	for _, want := range []string{"creates a short-lived read-only installation token", "selected-repository", "foreground demand", "Owner records remain after close", "explicitly approved fresh generation"} {
		if !strings.Contains(action, want) {
			t.Fatalf("action=%q missing %q", action, want)
		}
	}
}

func TestSetupRequirementActionsDescribeReplicaAndSignedBundleChecks(t *testing.T) {
	for _, test := range []struct {
		profile setupcore.Profile
		key     setupcore.CheckKey
		want    string
	}{
		{setupcore.ProfileKubernetesHA, setupcore.CheckReplicaReconciliationValidated, "two-instance"},
		{setupcore.ProfileAirGapped, setupcore.CheckSignedBundleValidated, "opaque"},
	} {
		plan, _ := setupcore.NewPlan(test.profile, "tenant-a", "repo-a", "owner", time.UnixMilli(1).UTC())
		found := false
		for _, requirement := range plan.Requirements() {
			if requirement.Key() != test.key {
				continue
			}
			found = true
			action := setupRequirementAction(requirement)
			if !strings.Contains(action, test.want) || strings.Contains(action, "No built-in") {
				t.Fatalf("%s action=%q", test.key, action)
			}
		}
		if !found {
			t.Fatalf("missing %s", test.key)
		}
	}
}
