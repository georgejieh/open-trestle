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
	plan, _, err := c.coordinator.Resume(ctx, scope)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	state, err := c.coordinator.Advance(ctx, plan, c.clock.Now().UTC())
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return controlplane.NewReviewRunReceipt(state)
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
	renewed, _, err := c.coordinator.RenewTaskLease(ctx, plan, lease, c.clock.Now().UTC())
	return renewed, err
}
func (c *LocalControl) CompleteTask(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	plan, err := c.GetRunPlan(ctx, scope)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	state, err := c.coordinator.CompleteTask(ctx, plan, lease, completion, c.clock.Now().UTC())
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return controlplane.NewReviewRunReceipt(state)
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
}
type RepositorySupervisor struct {
	journal   controlplane.RunJournal
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
	if nilWorkerValue(journal) || catalog.Validate() != nil || !validLocalScopeID(options.TenantID) || !validRepos || !validLocalWorkerIdentity(options.WorkerIdentity) || options.PollInterval < minimumPollInterval || options.PollInterval > maximumPollInterval || options.RenewalInterval < minimumRenewalInterval || options.RenewalInterval > maximumRenewalInterval || options.ExecutionTimeout < minimumExecutionTime || options.ExecutionTimeout > maximumExecutionTime || options.RenewalInterval >= options.ExecutionTimeout || nilWorkerValue(options.Clock) {
		return nil, ErrInvalidRepositorySupervisor
	}
	return &RepositorySupervisor{journal: journal, catalog: catalog, options: options, ready: make(chan struct{}), cursors: make(map[string]string)}, nil
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
			if ctx.Err() != nil {
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
			runner, err := New(control, s.catalog, Options{Scope: plan.Scope(), PollInterval: s.options.PollInterval, RenewalInterval: s.options.RenewalInterval, ExecutionTimeout: s.options.ExecutionTimeout})
			if err != nil {
				return workedAny, err
			}
			for {
				worked, settled, runErr := runner.RunOnce(ctx)
				if runErr != nil {
					return workedAny, fmt.Errorf("execute repository run: %w", runErr)
				}
				workedAny = workedAny || worked
				if settled || !worked {
					break
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
