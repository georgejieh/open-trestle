package worker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

const maximumSupervisorPlansPerPage = 100

var ErrInvalidRepositorySupervisor = errors.New("invalid repository worker supervisor")

type Clock interface{ Now() time.Time }

type LocalControl struct {
	coordinator    *controlplane.Coordinator
	journal        controlplane.RunJournal
	clock          Clock
	workerIdentity string
}

func NewLocalControl(journal controlplane.RunJournal, clock Clock, workerIdentity string) (*LocalControl, error) {
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil || nilWorkerValue(clock) || !validLocalWorkerIdentity(workerIdentity) {
		return nil, ErrInvalidWorker
	}
	return &LocalControl{coordinator: coordinator, journal: journal, clock: clock, workerIdentity: workerIdentity}, nil
}
func (c *LocalControl) GetRun(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	var receipt controlplane.ReviewRunReceipt
	operation := func(inner context.Context) error {
		plan, _, err := c.coordinator.Resume(inner, scope)
		if err != nil {
			return err
		}
		state, err := c.coordinator.Advance(inner, plan, c.clock.Now().UTC())
		if err != nil {
			return err
		}
		receipt, err = controlplane.NewReviewRunReceipt(state)
		return err
	}
	if journal, ok := c.journal.(*controlplane.FileRunJournal); ok {
		plan, found, err := journal.LoadPlan(ctx, scope)
		if err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		if !found {
			return controlplane.ReviewRunReceipt{}, controlplane.ErrRunNotOpened
		}
		err = journal.WithScopeIntent(ctx, scope, "worker-get-run", plan.Identity(), operation, func(inner context.Context) error {
			_, observed, err := c.coordinator.Resume(inner, scope)
			if err != nil {
				return err
			}
			if observed.HeadIdentity() != receipt.HeadIdentity() || observed.Revision() != receipt.Revision() {
				return controlplane.ErrRunJournalHeadConflict
			}
			return nil
		})
		return receipt, err
	}
	if err := operation(ctx); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return receipt, nil
}
func (c *LocalControl) GetRunPlan(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunPlan, error) {
	plan, found, err := c.journal.LoadPlan(ctx, scope)
	if err != nil {
		return controlplane.ReviewRunPlan{}, err
	}
	if !found {
		return controlplane.ReviewRunPlan{}, controlplane.ErrRunNotOpened
	}
	return plan, nil
}

func (c *LocalControl) ClaimTask(ctx context.Context, scope audit.ReviewScope, key, handler string) (controlplane.TaskLease, error) {
	plan, err := c.GetRunPlan(ctx, scope)
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	// Read-only preflight: validate that taskKey exists in the plan before
	// entering the effect gate, so a missing-key error does not enter quarantine.
	if _, exists := plan.Task(key); !exists {
		return controlplane.TaskLease{}, controlplane.ErrReviewTaskNotFound
	}
	if journal, ok := c.journal.(*controlplane.FileRunJournal); ok {
		var claimed controlplane.TaskLease
		var acquired bool
		err = journal.WithScopeIntent(ctx, scope, "worker-claim-task", plan.Identity(),
			func(inner context.Context) error {
				claimed, acquired, err = c.coordinator.ClaimTask(inner, plan, key, handler, c.workerIdentity, c.clock.Now().UTC())
				return err
			},
			func(inner context.Context) error {
				if err != nil {
					return err
				}
				if !acquired {
					// Conflict/no-op: no state was mutated; leave scope un-quarantined.
					return nil
				}
				// Mutated: coordinator appended TaskLeased. Verify the event identity
				// matches the lease returned by the effect so a non-idempotent mutation
				// that returned a different identity is quarantined.
				if claimed.EventIdentity() == "" {
					return controlplane.ErrRunJournalPersistence
				}
				persisted, present, readErr := journal.Head(inner, scope)
				if readErr != nil || !present || persisted.Identity() != claimed.EventIdentity() {
					return errors.Join(controlplane.ErrRunJournalPersistence, readErr)
				}
				return nil
			},
		)
		if err != nil {
			return controlplane.TaskLease{}, err
		}
		if !acquired {
			return controlplane.TaskLease{}, localConflict{}
		}
		return claimed, nil
	}
	// Non-file journal path: coordinator does everything inline.
	lease, acquired, err := c.coordinator.ClaimTask(ctx, plan, key, handler, c.workerIdentity, c.clock.Now().UTC())
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	if !acquired {
		return controlplane.TaskLease{}, localConflict{}
	}
	return lease, nil
}

func (c *LocalControl) RenewTaskLease(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease) (controlplane.TaskLease, error) {
	plan, err := c.GetRunPlan(ctx, scope)
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	if err := lease.Validate(); err != nil {
		return controlplane.TaskLease{}, err
	}
	if journal, ok := c.journal.(*controlplane.FileRunJournal); ok {
		var renewed controlplane.TaskLease
		err = journal.WithScopeIntent(ctx, scope, "worker-renew-task-lease", lease.Identity(),
			func(inner context.Context) error {
				renewed, _, err = c.coordinator.RenewTaskLease(inner, plan, lease, c.clock.Now().UTC())
				return err
			},
			func(inner context.Context) error {
				if err != nil {
					return err
				}
				// verify reads back the durable lease event identity and checks it matches
				// the returned lease. A mismatch means the effect produced a non-idempotent
				// result and must be quarantined.
				if renewed.EventIdentity() == "" {
					return controlplane.ErrRunJournalPersistence
				}
				_, observed, readErr := c.coordinator.Resume(inner, scope)
				if readErr != nil {
					return readErr
				}
				runtime, found := observed.Task(lease.TaskKey())
				if !found || runtime.LastEventIdentity() != renewed.EventIdentity() || runtime.Status() != controlplane.TaskRuntimeLeased {
					return controlplane.ErrRunJournalPersistence
				}
				return nil
			},
		)
		if err != nil {
			return controlplane.TaskLease{}, err
		}
		return renewed, nil
	}
	// Non-file journal path: coordinator does everything inline.
	renewed, _, err := c.coordinator.RenewTaskLease(ctx, plan, lease, c.clock.Now().UTC())
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	return renewed, nil
}

func (c *LocalControl) CompleteTask(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	plan, err := c.GetRunPlan(ctx, scope)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if err := lease.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if err := completion.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if journal, ok := c.journal.(*controlplane.FileRunJournal); ok {
		var receipt controlplane.ReviewRunReceipt
		err = journal.WithScopeIntent(ctx, scope, "worker-complete-task", lease.Identity(),
			func(inner context.Context) error {
				var state controlplane.ReviewRunState
				state, err = c.coordinator.CompleteTask(inner, plan, lease, completion, c.clock.Now().UTC())
				if err != nil {
					return err
				}
				receipt, err = controlplane.NewReviewRunReceipt(state)
				return err
			},
			func(inner context.Context) error {
				if err != nil {
					return err
				}
				// verify reads back the receipt's plan identity to confirm the
				// TaskSucceeded/TaskFailed event was committed under the correct plan.
				if receipt.PlanIdentity() != plan.Identity() {
					return controlplane.ErrRunJournalPersistence
				}
				_, observed, readErr := c.coordinator.Resume(inner, scope)
				if readErr != nil {
					return readErr
				}
				if observed.HeadIdentity() != receipt.HeadIdentity() || observed.Revision() != receipt.Revision() {
					return controlplane.ErrRunJournalPersistence
				}
				return nil
			},
		)
		if err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		return receipt, nil
	}
	// Non-file journal path: coordinator does everything inline.
	state, err := c.coordinator.CompleteTask(ctx, plan, lease, completion, c.clock.Now().UTC())
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return receipt, nil
}

type localConflict struct{}

func (localConflict) Error() string   { return "task not claimable" }
func (localConflict) StatusCode() int { return 409 }
func (localConflict) Code() string    { return "conflict" }

type RepositorySupervisorOptions struct {
	TenantID                                        string
	RepositoryIDs                                   []string
	WorkerIdentity                                  string
	PollInterval, RenewalInterval, ExecutionTimeout time.Duration
	Clock                                           Clock
	FinalizeSettled                                 bool
	OnTerminal                                      func(context.Context, controlplane.ReviewRunState) error
}
type RepositorySupervisor struct {
	journal   controlplane.RunJournal
	finalizer *controlplane.RunFinalizer
	catalog   controlplane.TaskHandlerCatalog
	options   RepositorySupervisorOptions
	ready     chan struct{}
	readyOnce sync.Once
	mu        sync.Mutex
	cursors   map[string]string
}

func NewRepositorySupervisor(journal controlplane.RunJournal, catalog controlplane.TaskHandlerCatalog, options RepositorySupervisorOptions) (*RepositorySupervisor, error) {
	canonical := append([]string(nil), options.RepositoryIDs...)
	sort.Strings(canonical)
	validRepos := len(canonical) > 0 && len(canonical) <= 64
	for i, v := range canonical {
		if !validLocalScopeID(v) || i > 0 && v == canonical[i-1] {
			validRepos = false
		}
	}
	options.RepositoryIDs = canonical
	if nilWorkerValue(journal) || catalog.Validate() != nil || !validLocalScopeID(options.TenantID) || !validRepos || !validLocalWorkerIdentity(options.WorkerIdentity) || options.PollInterval < minimumPollInterval || options.PollInterval > maximumPollInterval || options.RenewalInterval < minimumRenewalInterval || options.RenewalInterval > maximumRenewalInterval || options.ExecutionTimeout < minimumExecutionTime || options.ExecutionTimeout > maximumExecutionTime || options.RenewalInterval >= options.ExecutionTimeout || nilWorkerValue(options.Clock) || options.OnTerminal != nil && !options.FinalizeSettled {
		return nil, ErrInvalidRepositorySupervisor
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		return nil, ErrInvalidRepositorySupervisor
	}
	return &RepositorySupervisor{journal: journal, finalizer: finalizer, catalog: catalog, options: options, ready: make(chan struct{}), cursors: make(map[string]string)}, nil
}
func (s *RepositorySupervisor) Ready() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.ready
}
func (s *RepositorySupervisor) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidRepositorySupervisor
	}
	for {
		_, err := s.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil && !errors.Is(err, ErrWorkerDrain) {
				return nil
			}
			return err
		}
		s.readyOnce.Do(func() { close(s.ready) })
		timer := time.NewTimer(s.options.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}
func (s *RepositorySupervisor) RunOnce(ctx context.Context) (bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrInvalidRepositorySupervisor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	workedAny := false
	for _, repository := range s.options.RepositoryIDs {
		after := s.cursors[repository]
		plans, err := s.journal.ListPlans(ctx, s.options.TenantID, repository, after, maximumSupervisorPlansPerPage)
		if err != nil {
			return workedAny, err
		}
		for _, plan := range plans {
			control, err := NewLocalControl(s.journal, s.options.Clock, s.options.WorkerIdentity)
			if err != nil {
				return workedAny, err
			}
			runner, err := New(control, s.catalog, Options{Scope: plan.Scope(), PollInterval: s.options.PollInterval, RenewalInterval: s.options.RenewalInterval, ExecutionTimeout: s.options.ExecutionTimeout, Clock: s.options.Clock})
			if err != nil {
				return workedAny, err
			}
			settled := false
			for {
				worked, runSettled, runErr := runner.RunOnce(ctx)
				if runErr != nil {
					return workedAny, fmt.Errorf("execute repository run: %w", runErr)
				}
				workedAny = workedAny || worked
				settled = runSettled
				if settled || !worked {
					break
				}
			}
			if settled && s.options.FinalizeSettled {
				terminal, finalized, finalizeErr := s.finalizer.ReconcileRun(ctx, plan.Scope(), s.options.Clock.Now().UTC())
				if finalizeErr != nil {
					return workedAny, fmt.Errorf("finalize repository run: %w", finalizeErr)
				}
				workedAny = workedAny || finalized
				if terminal.Status() != controlplane.ReviewRunActive && s.options.OnTerminal != nil {
					if err := s.options.OnTerminal(ctx, terminal); err != nil {
						return workedAny, fmt.Errorf("project terminal repository run: %w", err)
					}
				}
			}
		}
		if len(plans) < maximumSupervisorPlansPerPage {
			s.cursors[repository] = ""
		} else {
			next := plans[len(plans)-1].Scope().ReviewRunID()
			if next <= after {
				return workedAny, ErrWorkerState
			}
			s.cursors[repository] = next
		}
	}
	return workedAny, nil
}

func nilWorkerValue(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return ref.IsNil()
	default:
		return false
	}
}
func validLocalScopeID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '/' || r == ':') {
			return false
		}
	}
	return true
}
func validLocalWorkerIdentity(value string) bool { return validLocalScopeID(value) }

var _ Control = (*LocalControl)(nil)
