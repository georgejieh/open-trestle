package setup

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type testChecker struct {
	key      CheckKey
	identity string
	result   CheckResult
	calls    int
}

func (c *testChecker) Key() CheckKey                           { return c.key }
func (c *testChecker) CheckerIdentity() string                 { return c.identity }
func (c *testChecker) Check(context.Context, Plan) CheckResult { c.calls++; return c.result }

type testRunnerClock struct{ at time.Time }

func (c testRunnerClock) Now() time.Time { return c.at }
func TestRunnerAppliesOnlyApprovedCheckerResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	identity, _ := catalog.Resolve(key)
	checker := &testChecker{key: key, identity: identity, result: NewPassedCheckResult(setupDigest("evidence"))}
	runner, err := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(1)})
	if err != nil {
		t.Fatal(err)
	}
	next, receipt, err := runner.Run(context.Background(), key)
	if err != nil || next.Revision() != 2 || receipt.PlanIdentity() != plan.Identity() || checker.calls != 1 {
		t.Fatalf("run=%v revision=%d calls=%d", err, next.Revision(), checker.calls)
	}
	current, err := state.Current(context.Background())
	if err != nil || current.Identity() != next.Identity() || len(current.Receipts()) != 1 {
		t.Fatalf("current=%v", err)
	}
}
func TestRunnerRejectsUnapprovedOrMalformedCheckerWithoutExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	key := pendingRequirement(t, plan)
	checker := &testChecker{key: key, identity: setupDigest("wrong"), result: NewPassedCheckResult(setupDigest("evidence"))}
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(1)})
	if _, _, err := runner.Run(context.Background(), key); !errors.Is(err, ErrCheckNotAuthorized) || checker.calls != 0 {
		t.Fatalf("unauthorized=%v calls=%d", err, checker.calls)
	}
	if current, _ := state.Current(context.Background()); current.Revision() != 1 {
		t.Fatal("state changed")
	}
}
func TestRunnerRecordsClosedRecoveryAndFencesStaleWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	keys := []CheckKey{}
	for _, r := range plan.Requirements() {
		if r.State() == CheckPending {
			keys = append(keys, r.Key())
		}
	}
	firstID, _ := catalog.Resolve(keys[0])
	first := &testChecker{key: keys[0], identity: firstID, result: NewFailedCheckResult(keys[0], CheckBlocked, setupDigest("blocked"))}
	runner, _ := NewRunner(state, []Checker{first}, testRunnerClock{setupTime(1)})
	next, _, err := runner.Run(context.Background(), keys[0])
	if err != nil || next.Status() != StatusBlocked || next.Requirements()[4].RecoveryAction() != recoveryForKey(keys[0]) {
		t.Fatalf("blocked=%v", err)
	}
	staleResult := NewPassedCheckResult(setupDigest("stale"))
	staleReceipt, _ := newCheckReceipt(plan, keys[0], firstID, staleResult.State(), staleResult.EvidenceIdentity(), staleResult.RecoveryAction(), setupTime(2))
	if _, err := state.applyReceipt(context.Background(), staleReceipt, catalog); !errors.Is(err, ErrStaleCheckReceipt) {
		t.Fatalf("stale=%v", err)
	}
}
func TestRunnerHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	identity, _ := catalog.Resolve(key)
	checker := &testChecker{key: key, identity: identity, result: NewPassedCheckResult(setupDigest("evidence"))}
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(1)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := runner.Run(ctx, key); err == nil || checker.calls != 0 {
		t.Fatalf("cancel=%v calls=%d", err, checker.calls)
	}
}

func TestRunnerResumesDurableReceiptWithoutRerunningChecker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	identity, _ := catalog.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, identity, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	_ = state.persistReceipt(2, receipt)
	checker := &testChecker{key: key, identity: identity, result: NewPassedCheckResult(setupDigest("different"))}
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(2)})
	next, got, err := runner.Run(context.Background(), key)
	if err != nil || next.Revision() != 2 || got.Identity() != receipt.Identity() || checker.calls != 0 {
		t.Fatalf("resume=%v revision=%d calls=%d", err, next.Revision(), checker.calls)
	}
}

func TestNewRunnerRejectsTypedNilBeforeSortingOrOtherCheckerCalls(t *testing.T) {
	var typedNil *testChecker
	other := &testChecker{key: CheckBackupValidated, identity: setupDigest("other")}
	if runner, err := NewRunner(&StateFile{}, []Checker{other, typedNil}, testRunnerClock{setupTime(1)}); !errors.Is(err, ErrInvalidCheckerRuntime) || runner != nil || other.calls != 0 {
		t.Fatalf("runner=%#v err=%v calls=%d", runner, err, other.calls)
	}
	if runner, err := NewRunner(nil, []Checker{other}, testRunnerClock{setupTime(1)}); !errors.Is(err, ErrInvalidCheckerRuntime) || runner != nil {
		t.Fatalf("nil state=%#v %v", runner, err)
	}
}

func TestRunnerExpectedPlanFencesCheckerExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, _ := OpenStateFile(path)
	defer state.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = state.Initialize(context.Background(), plan)
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	identity, _ := catalog.Resolve(key)
	checker := &testChecker{key: key, identity: identity, result: NewPassedCheckResult(setupDigest("expected"))}
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(1)})
	if _, _, err := runner.RunExpected(context.Background(), key, setupDigest("stale-plan")); !errors.Is(err, ErrStateConflict) || checker.calls != 0 {
		t.Fatalf("stale=%v calls=%d", err, checker.calls)
	}
	next, _, err := runner.RunExpected(context.Background(), key, plan.Identity())
	if err != nil || next.Revision() != 2 || checker.calls != 1 {
		t.Fatalf("expected=%v revision=%d calls=%d", err, next.Revision(), checker.calls)
	}
}
