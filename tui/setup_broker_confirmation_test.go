package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupBrokerTUIClock struct{}

func (setupBrokerTUIClock) Now() time.Time { return time.UnixMilli(200).UTC() }

// The service fixture measures terminal dispatch, not startup approvals or issuance.
type setupBrokerTUIBoundary struct {
	state                                 *setupcore.StateFile
	runner                                *setupcore.Runner
	initial                               setupcore.Plan
	currentCalls, runCalls, probeCalls    int
	keys                                  []setupcore.CheckKey
	expected                              []string
	unavailable, changeBeforeConfirmation bool
}

func (b *setupBrokerTUIBoundary) AuthorityIdentity() string     { return strings.Repeat("a", 64) }
func (b *setupBrokerTUIBoundary) ConfigurationIdentity() string { return strings.Repeat("b", 64) }
func (b *setupBrokerTUIBoundary) Probe(context.Context) setupcore.IntegrationPermissionProbeResult {
	b.probeCalls++
	return setupcore.NewVerifiedIntegrationPermissionProbeResult(b.AuthorityIdentity(), strings.Repeat("c", 64))
}
func (b *setupBrokerTUIBoundary) Current(ctx context.Context) (setupcore.Plan, error) {
	b.currentCalls++
	if b.changeBeforeConfirmation && b.currentCalls == 2 {
		checker, err := setupcore.NewObserverCredentialPostureChecker(func(name string) string {
			switch name {
			case "OPEN_TRESTLE_API_TOKEN":
				return "operator-" + strings.Repeat("o", 40)
			case "OPEN_TRESTLE_OBSERVER_TOKEN":
				return "observer-" + strings.Repeat("v", 40)
			}
			return ""
		})
		if err != nil {
			return setupcore.Plan{}, err
		}
		runner, err := setupcore.NewRunner(b.state, []setupcore.Checker{checker}, setupBrokerTUIClock{})
		if err != nil {
			return setupcore.Plan{}, err
		}
		if _, _, err = runner.RunExpected(ctx, setupcore.CheckObserverCredentialPostureValidated, b.initial.Identity()); err != nil {
			return setupcore.Plan{}, err
		}
	}
	return b.state.Current(ctx)
}
func (b *setupBrokerTUIBoundary) RunCheck(ctx context.Context, key setupcore.CheckKey, expected string) (setupcore.Plan, setupcore.CheckReceipt, error) {
	b.runCalls++
	b.keys = append(b.keys, key)
	b.expected = append(b.expected, expected)
	if b.unavailable {
		return setupcore.Plan{}, setupcore.CheckReceipt{}, ErrSetupCheckUnavailable
	}
	return b.runner.RunExpected(ctx, key, expected)
}
func newSetupBrokerTUIBoundary(t *testing.T) *setupBrokerTUIBoundary {
	t.Helper()
	b := &setupBrokerTUIBoundary{}
	var err error
	b.initial, err = setupcore.NewCurrentPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", time.UnixMilli(100).UTC())
	if err != nil {
		t.Fatal(err)
	}
	b.state, err = setupcore.OpenStateFile(filepath.Join(t.TempDir(), "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.state.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = b.state.Initialize(context.Background(), b.initial); err != nil {
		t.Fatal(err)
	}
	checker, err := setupcore.NewIntegrationPermissionChecker(b.initial, b.AuthorityIdentity(), "owner", b)
	if err != nil {
		t.Fatal(err)
	}
	b.runner, err = setupcore.NewRunner(b.state, []setupcore.Checker{checker}, setupBrokerTUIClock{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (b *setupBrokerTUIBoundary) selectIntegration(t *testing.T) string {
	t.Helper()
	requirements := b.initial.Requirements()
	for index, requirement := range requirements {
		if requirement.Key() == setupcore.CheckIntegrationPermissionsValidated {
			return strings.Repeat("k\n", len(requirements)) + strings.Repeat("j\n", index)
		}
	}
	t.Fatal("integration requirement missing")
	return ""
}
func (b *setupBrokerTUIBoundary) run(t *testing.T, input io.Reader, once bool) string {
	t.Helper()
	var output bytes.Buffer
	interface_, err := NewSetup(b, input, &output, SetupOptions{Width: 240, Plain: true, Once: once})
	if err != nil {
		t.Fatal(err)
	}
	if b.currentCalls != 0 || b.runCalls != 0 || b.probeCalls != 0 {
		t.Fatal("construction dispatched service")
	}
	if err = interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return output.String()
}
func (b *setupBrokerTUIBoundary) unchanged(t *testing.T) {
	t.Helper()
	plan, err := b.state.Current(context.Background())
	if err != nil || plan.Identity() != b.initial.Identity() || len(plan.Receipts()) != 0 {
		t.Fatalf("state changed: %v", err)
	}
}

func TestSetupBrokerTUIExactArmedCommandRunsOnceWithExpectedPlan(t *testing.T) {
	b := newSetupBrokerTUIBoundary(t)
	commands := b.selectIntegration(t) + "x\nrun integration_permissions_validated\nrun integration_permissions_validated\nq\n"
	output := b.run(t, strings.NewReader(commands), false)
	if b.runCalls != 1 || b.probeCalls != 1 || len(b.keys) != 1 || b.keys[0] != setupcore.CheckIntegrationPermissionsValidated || len(b.expected) != 1 || b.expected[0] != b.initial.Identity() {
		t.Fatalf("dispatch=%d probe=%d keys=%v expected=%v", b.runCalls, b.probeCalls, b.keys, b.expected)
	}
	plan, err := b.state.Current(context.Background())
	if err != nil || plan.Revision() != b.initial.Revision()+1 || len(plan.Receipts()) != 1 || plan.Receipts()[0].State() != setupcore.CheckPassed || plan.Receipts()[0].PlanIdentity() != b.initial.Identity() {
		t.Fatalf("receipt=%v", err)
	}
	if !strings.Contains(output, "Check completed: passed.") || !strings.Contains(output, "Confirmation did not match") {
		t.Fatal(output)
	}
}

func TestSetupBrokerTUIRefusesUnarmedOrInvalidatedConfirmation(t *testing.T) {
	cases := map[string]string{
		"unarmed":                           "run integration_permissions_validated\n",
		"arm_only":                          "x\n",
		"wrong_key":                         "x\nrun webhook_validated\nrun integration_permissions_validated\n",
		"browser_phrase_is_not_tui_command": "x\ncreate GitHub installation token and run integration_permissions_validated\nrun integration_permissions_validated\n",
		"case_mismatch":                     "x\nRUN integration_permissions_validated\nrun integration_permissions_validated\n",
		"extra_word":                        "x\nrun integration_permissions_validated now\nrun integration_permissions_validated\n",
		"navigation_clears":                 "x\nj\nk\nrun integration_permissions_validated\n",
		"refresh_clears":                    "x\nr\nrun integration_permissions_validated\n",
		"blank_clears":                      "x\n\nrun integration_permissions_validated\n",
		"unknown_clears":                    "x\nhelp\nrun integration_permissions_validated\n",
	}
	for name, commands := range cases {
		t.Run(name, func(t *testing.T) {
			b := newSetupBrokerTUIBoundary(t)
			b.run(t, strings.NewReader(b.selectIntegration(t)+commands+"q\n"), false)
			if b.runCalls != 0 || b.probeCalls != 0 {
				t.Fatalf("run=%d probe=%d", b.runCalls, b.probeCalls)
			}
			b.unchanged(t)
		})
	}
}

func TestSetupBrokerTUIStalePlanRefusesBeforeRunCheck(t *testing.T) {
	b := newSetupBrokerTUIBoundary(t)
	b.changeBeforeConfirmation = true
	output := b.run(t, strings.NewReader(b.selectIntegration(t)+"x\nrun integration_permissions_validated\nq\n"), false)
	if b.currentCalls != 2 || b.runCalls != 0 || b.probeCalls != 0 {
		t.Fatalf("current=%d run=%d probe=%d", b.currentCalls, b.runCalls, b.probeCalls)
	}
	if !strings.Contains(output, "Plan changed; refresh before running the check.") {
		t.Fatal(output)
	}
	plan, err := b.state.Current(context.Background())
	if err != nil || plan.RootIdentity() != b.initial.RootIdentity() || plan.Identity() == b.initial.Identity() || len(plan.Receipts()) != 1 || plan.Receipts()[0].Key() != setupcore.CheckObserverCredentialPostureValidated {
		t.Fatalf("stale fixture=%v", err)
	}
}

func TestSetupBrokerTUIUnavailableServiceDoesNotReplayConfirmation(t *testing.T) {
	b := newSetupBrokerTUIBoundary(t)
	b.unavailable = true
	output := b.run(t, strings.NewReader(b.selectIntegration(t)+"x\nrun integration_permissions_validated\nrun integration_permissions_validated\nq\n"), false)
	if b.runCalls != 1 || b.probeCalls != 0 || len(b.expected) != 1 || b.expected[0] != b.initial.Identity() {
		t.Fatalf("run=%d probe=%d expected=%v", b.runCalls, b.probeCalls, b.expected)
	}
	if !strings.Contains(output, "No checker is configured for this requirement.") {
		t.Fatal(output)
	}
	b.unchanged(t)
}

type setupBrokerTUIInput struct{ reads int }

func (r *setupBrokerTUIInput) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("render-only must not read commands")
}

func TestSetupBrokerTUIOnceRendersWithoutReadingCommands(t *testing.T) {
	b := newSetupBrokerTUIBoundary(t)
	input := &setupBrokerTUIInput{}
	output := b.run(t, input, true)
	if input.reads != 0 || b.currentCalls != 1 || b.runCalls != 0 || b.probeCalls != 0 {
		t.Fatalf("input=%d current=%d run=%d probe=%d", input.reads, b.currentCalls, b.runCalls, b.probeCalls)
	}
	if !strings.Contains(output, "OPEN TRESTLE SETUP") {
		t.Fatal(output)
	}
	b.unchanged(t)
}

func TestSetupBrokerTUIGuidanceDisclosesCredentialEffects(t *testing.T) {
	b := newSetupBrokerTUIBoundary(t)
	output := b.run(t, strings.NewReader(b.selectIntegration(t)+"x\nq\n"), false)
	frames := strings.Split(output, "---\n")
	last := strings.ToLower(strings.Join(strings.Fields(frames[len(frames)-1]), " "))
	for _, required := range []string{"creat", "installation token", "short-lived", "read", "owner", "record", "foreground", "renew"} {
		if !strings.Contains(last, required) {
			t.Fatalf("missing %q in final frame: %s", required, last)
		}
	}
	if !strings.Contains(last, "read-only") && !strings.Contains(last, "read-scoped") && !strings.Contains(last, "read token") {
		t.Fatalf("missing token read scope: %s", last)
	}
	for _, misleading := range []string{"get-only", "read-only selected-repository inspection", "no token creation"} {
		if strings.Contains(last, misleading) {
			t.Fatalf("misleading guidance: %s", last)
		}
	}
	// The armed notice remains separate from the selected requirement's action text.
	frame := frames[len(frames)-1]
	beforeCommands, _, ok := strings.Cut(frame, "\nCommands:")
	if !ok {
		t.Fatal("commands footer missing")
	}
	sections := strings.Split(strings.TrimSpace(beforeCommands), "\n\n")
	notice := strings.ToLower(sections[len(sections)-1])
	if !strings.Contains(notice, "run integration_permissions_validated") || !strings.Contains(notice, "creat") || !strings.Contains(notice, "token") {
		t.Fatalf("arming hides credential creation: %q", notice)
	}
	if b.runCalls != 0 || b.probeCalls != 0 {
		t.Fatal("guidance dispatched a check")
	}
	b.unchanged(t)
}
