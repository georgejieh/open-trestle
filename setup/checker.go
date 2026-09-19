package setup

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"
)

var (
	ErrInvalidCheckResult    = errors.New("invalid setup check result")
	ErrInvalidCheckerRuntime = errors.New("invalid setup checker runtime")
)

// CheckResult is a closed content-free checker outcome.
type CheckResult struct {
	state            CheckState
	evidenceIdentity string
	recovery         RecoveryAction
}

// NewPassedCheckResult records evidence for a successful check.
func NewPassedCheckResult(evidenceIdentity string) CheckResult {
	return CheckResult{state: CheckPassed, evidenceIdentity: evidenceIdentity}
}

// NewFailedCheckResult records blocked or unavailable evidence with the required recovery.
func NewFailedCheckResult(key CheckKey, state CheckState, evidenceIdentity string) CheckResult {
	if state != CheckBlocked && state != CheckUnavailable {
		return CheckResult{}
	}
	return CheckResult{state: state, evidenceIdentity: evidenceIdentity, recovery: recoveryForKey(key)}
}
func (r CheckResult) State() CheckState              { return r.state }
func (r CheckResult) EvidenceIdentity() string       { return r.evidenceIdentity }
func (r CheckResult) RecoveryAction() RecoveryAction { return r.recovery }
func (r CheckResult) validate(key CheckKey) error {
	if !validCheckKey(key) || deterministicCheck(key) || !nonzeroSetupDigest(r.evidenceIdentity) || r.state == CheckPassed && r.recovery != RecoveryNone || (r.state == CheckBlocked || r.state == CheckUnavailable) && r.recovery != recoveryForKey(key) || (r.state != CheckPassed && r.state != CheckBlocked && r.state != CheckUnavailable) {
		return ErrInvalidCheckResult
	}
	return nil
}

// Checker performs one approved effect-free setup validation.
type Checker interface {
	Key() CheckKey
	CheckerIdentity() string
	Check(context.Context, Plan) CheckResult
}
type checkerRuntime struct{ checkers map[CheckKey]Checker }

func newCheckerRuntime(checkers []Checker) (checkerRuntime, error) {
	if len(checkers) == 0 || len(checkers) > maxSetupRequirements {
		return checkerRuntime{}, ErrInvalidCheckerRuntime
	}
	type entry struct {
		key      CheckKey
		identity string
		checker  Checker
	}
	entries := make([]entry, len(checkers))
	for i, checker := range checkers {
		if nilSetupInterface(checker) {
			return checkerRuntime{}, ErrInvalidCheckerRuntime
		}
		key, identity := checker.Key(), checker.CheckerIdentity()
		if !validCheckKey(key) || deterministicCheck(key) || !nonzeroSetupDigest(identity) {
			return checkerRuntime{}, ErrInvalidCheckerRuntime
		}
		entries[i] = entry{key, identity, checker}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	runtime := checkerRuntime{checkers: make(map[CheckKey]Checker, len(entries))}
	for i, value := range entries {
		if i > 0 && value.key == entries[i-1].key {
			return checkerRuntime{}, ErrInvalidCheckerRuntime
		}
		runtime.checkers[value.key] = value.checker
	}
	return runtime, nil
}
func (r checkerRuntime) resolve(key CheckKey) (Checker, bool) {
	checker, ok := r.checkers[key]
	return checker, ok
}

// RunnerClock supplies canonical check observation time.
type RunnerClock interface{ Now() time.Time }

// Runner executes approved checkers and persists receipt-driven transitions.
type Runner struct {
	state   *StateFile
	runtime checkerRuntime
	clock   RunnerClock
}

// NewRunner composes an exact checker runtime around protected setup state.
func NewRunner(state *StateFile, checkers []Checker, clock RunnerClock) (*Runner, error) {
	if state == nil || nilSetupInterface(clock) {
		return nil, ErrInvalidCheckerRuntime
	}
	runtime, err := newCheckerRuntime(checkers)
	if err != nil {
		return nil, ErrInvalidCheckerRuntime
	}
	return &Runner{state: state, runtime: runtime, clock: clock}, nil
}

// Run executes and persists one exact setup check.
func (r *Runner) Run(ctx context.Context, key CheckKey) (Plan, CheckReceipt, error) {
	return r.run(ctx, key, "")
}

// RunExpected executes only when the protected plan still has the caller-confirmed identity.
func (r *Runner) RunExpected(ctx context.Context, key CheckKey, expectedPlanIdentity string) (Plan, CheckReceipt, error) {
	return r.run(ctx, key, expectedPlanIdentity)
}
func (r *Runner) run(ctx context.Context, key CheckKey, expectedPlanIdentity string) (Plan, CheckReceipt, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || expectedPlanIdentity != "" && !nonzeroSetupDigest(expectedPlanIdentity) {
		return Plan{}, CheckReceipt{}, ErrInvalidCheckerRuntime
	}
	// Refuse historical effect authority before even considering a durable
	// pending receipt. Expected-plan approval retains its existing priority.
	if key == CheckIntegrationPermissionsValidated || key == CheckWebhookValidated {
		head, err := r.state.Current(ctx)
		if err != nil {
			return Plan{}, CheckReceipt{}, err
		}
		if expectedPlanIdentity != "" && head.Identity() != expectedPlanIdentity {
			return Plan{}, CheckReceipt{}, ErrStateConflict
		}
		if !currentIntegrationOperationAuthorized(head, key) {
			return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
		}
	}
	pending, foundPending, pendingErr := r.state.PendingReceipt(ctx)
	if pendingErr != nil {
		return Plan{}, CheckReceipt{}, pendingErr
	}
	if foundPending {
		checker, found := r.runtime.resolve(pending.Key())
		plan, currentErr := r.state.Current(ctx)
		if currentErr != nil {
			return Plan{}, CheckReceipt{}, currentErr
		}
		if expectedPlanIdentity != "" && plan.Identity() != expectedPlanIdentity {
			return Plan{}, CheckReceipt{}, ErrStateConflict
		}
		if !currentIntegrationOperationAuthorized(plan, key) {
			return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
		}
		approved, approvedFound := plan.checkerCatalog.Resolve(pending.Key())
		if pending.Key() != key || !found || !approvedFound || checker.Key() != key || checker.CheckerIdentity() != approved || pending.CheckerIdentity() != approved {
			return Plan{}, CheckReceipt{}, ErrStateConflict
		}
		next, applyErr := r.state.applyReceipt(ctx, pending, plan.checkerCatalog)
		if applyErr != nil {
			return Plan{}, CheckReceipt{}, applyErr
		}
		return next, pending, nil
	}
	plan, err := r.state.Current(ctx)
	if err != nil {
		return Plan{}, CheckReceipt{}, err
	}
	if expectedPlanIdentity != "" && plan.Identity() != expectedPlanIdentity {
		return Plan{}, CheckReceipt{}, ErrStateConflict
	}
	if !currentIntegrationOperationAuthorized(plan, key) {
		return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
	}
	checker, found := r.runtime.resolve(key)
	if !found {
		return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
	}
	approved, found := plan.checkerCatalog.Resolve(key)
	if !found || approved != checker.CheckerIdentity() {
		return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
	}
	result := checker.Check(ctx, plan)
	if checker.Key() != key || checker.CheckerIdentity() != approved {
		return Plan{}, CheckReceipt{}, ErrCheckNotAuthorized
	}
	if ctx.Err() != nil {
		return Plan{}, CheckReceipt{}, ErrInvalidCheckerRuntime
	}
	if result.validate(key) != nil {
		return Plan{}, CheckReceipt{}, ErrInvalidCheckResult
	}
	at, ok := normalizeSetupTime(r.clock.Now())
	if !ok {
		return Plan{}, CheckReceipt{}, ErrInvalidCheckerRuntime
	}
	if !at.After(plan.updatedAt) {
		at = plan.updatedAt.Add(time.Millisecond)
	}
	receipt, err := newCheckReceipt(plan, key, approved, result.state, result.evidenceIdentity, result.recovery, at)
	if err != nil {
		return Plan{}, CheckReceipt{}, err
	}
	next, err := r.state.applyReceipt(ctx, receipt, plan.checkerCatalog)
	if err != nil {
		return Plan{}, CheckReceipt{}, err
	}
	return next, receipt, nil
}
func passedRequirementReceiptIdentity(plan Plan, key CheckKey) string {
	index, found := planRequirementIndex(plan, key)
	if !found || plan.requirements[index].state != CheckPassed || !nonzeroSetupDigest(plan.requirements[index].receiptIdentity) {
		return ""
	}
	for i := len(plan.receipts) - 1; i >= 0; i-- {
		receipt := plan.receipts[i]
		if receipt.key == key && receipt.identity == plan.requirements[index].receiptIdentity && receipt.state == CheckPassed {
			return receipt.identity
		}
	}
	return ""
}

func nilSetupInterface(value any) bool {
	if value == nil {
		return true
	}
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	}
	return false
}

func (r *Runner) String() string   { return "setup checker runner" }
func (r *Runner) GoString() string { return "setup.Runner{<redacted>}" }
func (r *Runner) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, r.String(), r.GoString())
}
func writeSetupFormat(state fmt.State, verb rune, plain, goValue string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = goValue
	}
	_, _ = state.Write([]byte(value))
}
