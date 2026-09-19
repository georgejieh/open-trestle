package controlplane

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"

	"github.com/georgejieh/open-trestle/audit"
)

const maxRunJournalReadLimit = 1_000

var (
	// ErrInvalidRunJournal identifies a missing journal implementation.
	ErrInvalidRunJournal = errors.New("invalid run journal")
	// ErrInvalidRunJournalContext identifies a nil operation context.
	ErrInvalidRunJournalContext = errors.New("invalid run journal context")
	// ErrRunJournalContextDone identifies a canceled operation context.
	ErrRunJournalContextDone = errors.New("run journal context done")
	// ErrRunJournalHeadConflict identifies a failed optimistic head comparison.
	ErrRunJournalHeadConflict = errors.New("run journal head conflict")
	// ErrRunJournalSequenceMismatch identifies an event other than the next sequence.
	ErrRunJournalSequenceMismatch = errors.New("run journal sequence mismatch")
	// ErrRunJournalChainMismatch identifies an event with the wrong predecessor.
	ErrRunJournalChainMismatch = errors.New("run journal chain mismatch")
	// ErrInvalidRunJournalReadLimit identifies an unusable page bound.
	ErrInvalidRunJournalReadLimit = errors.New("invalid run journal read limit")
	// ErrRunPlanConflict identifies another immutable plan in the same scope.
	ErrRunPlanConflict = errors.New("review run plan conflict")
	// ErrInvalidRunPlanQuery identifies an unsafe scope filter or page bound.
	ErrInvalidRunPlanQuery = errors.New("invalid review run plan query")
)

// RunJournal atomically appends and reads one review-run event stream.
type RunJournal interface {
	SavePlan(context.Context, ReviewRunPlan) error
	LoadPlan(context.Context, audit.ReviewScope) (ReviewRunPlan, bool, error)
	ListPlans(context.Context, string, string, string, int) ([]ReviewRunPlan, error)
	Head(context.Context, audit.ReviewScope) (RunEvent, bool, error)
	Append(context.Context, string, RunEvent) error
	Read(context.Context, audit.ReviewScope, uint64, int) ([]RunEvent, error)
}

// MemoryRunJournal is a concurrency-safe in-memory journal for local execution and tests.
type MemoryRunJournal struct {
	mu      sync.RWMutex
	streams map[string][]RunEvent
	plans   map[string]ReviewRunPlan
}

func NewMemoryRunJournal() *MemoryRunJournal {
	return &MemoryRunJournal{streams: make(map[string][]RunEvent), plans: make(map[string]ReviewRunPlan)}
}
func (j *MemoryRunJournal) SavePlan(ctx context.Context, plan ReviewRunPlan) error {
	if isNilRunJournalContext(ctx) {
		return ErrInvalidRunJournalContext
	}
	if j == nil {
		return ErrInvalidRunJournal
	}
	if err := ctx.Err(); err != nil {
		return ErrRunJournalContextDone
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, found := j.plans[plan.Scope().Identity()]; found {
		if existing.Identity() == plan.Identity() {
			return nil
		}
		return ErrRunPlanConflict
	}
	stream := j.streams[plan.Scope().Identity()]
	if len(stream) != 0 && stream[0].PlanIdentity() != plan.Identity() {
		return ErrRunPlanConflict
	}
	j.plans[plan.Scope().Identity()] = plan
	return nil
}
func (j *MemoryRunJournal) LoadPlan(ctx context.Context, scope audit.ReviewScope) (ReviewRunPlan, bool, error) {
	if err := validateRunJournalOperation(ctx, j, scope); err != nil {
		return ReviewRunPlan{}, false, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	plan, found := j.plans[scope.Identity()]
	return plan, found, nil
}

func (j *MemoryRunJournal) ListPlans(ctx context.Context, tenantID, repositoryID, afterRunID string, limit int) ([]ReviewRunPlan, error) {
	if isNilRunJournalContext(ctx) {
		return nil, ErrInvalidRunJournalContext
	}
	if j == nil {
		return nil, ErrInvalidRunJournal
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrRunJournalContextDone
	}
	if !validRunPlanQuery(tenantID) || !validRunPlanQuery(repositoryID) || afterRunID != "" && !validRunPlanQuery(afterRunID) || limit <= 0 || limit > maxRunJournalReadLimit {
		return nil, ErrInvalidRunPlanQuery
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	plans := make([]ReviewRunPlan, 0)
	for _, plan := range j.plans {
		if plan.Scope().TenantID() == tenantID && plan.Scope().RepositoryID() == repositoryID && plan.Scope().ReviewRunID() > afterRunID {
			plans = append(plans, plan)
		}
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Scope().ReviewRunID() < plans[j].Scope().ReviewRunID() })
	if len(plans) > limit {
		plans = plans[:limit]
	}
	return plans, nil
}

func (j *MemoryRunJournal) Head(ctx context.Context, scope audit.ReviewScope) (RunEvent, bool, error) {
	if err := validateRunJournalOperation(ctx, j, scope); err != nil {
		return RunEvent{}, false, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	events := j.streams[scope.Identity()]
	if len(events) == 0 {
		return RunEvent{}, false, nil
	}
	return events[len(events)-1], true, nil
}
func (j *MemoryRunJournal) Append(ctx context.Context, expectedHead string, event RunEvent) error {
	if isNilRunJournalContext(ctx) {
		return ErrInvalidRunJournalContext
	}
	if j == nil {
		return ErrInvalidRunJournal
	}
	if err := ctx.Err(); err != nil {
		return ErrRunJournalContextDone
	}
	if err := event.Validate(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	events := j.streams[event.Scope().Identity()]
	if plan, found := j.plans[event.Scope().Identity()]; found && plan.Identity() != event.PlanIdentity() {
		return ErrRunPlanConflict
	}
	if len(events) > 0 && events[0].PlanIdentity() != event.PlanIdentity() {
		return ErrRunPlanConflict
	}
	if len(events) > 0 && events[len(events)-1].Identity() == event.Identity() {
		return nil
	}
	actualHead := ""
	if len(events) > 0 {
		actualHead = events[len(events)-1].Identity()
	}
	if actualHead != expectedHead {
		return ErrRunJournalHeadConflict
	}
	wantSequence := uint64(len(events) + 1)
	if event.Sequence() != wantSequence {
		return ErrRunJournalSequenceMismatch
	}
	if event.PreviousIdentity() != actualHead {
		return ErrRunJournalChainMismatch
	}
	if len(events) >= maxRunJournalStreamEvents {
		return ErrRunJournalStreamTooLarge
	}
	j.streams[event.Scope().Identity()] = append(events, event)
	return nil
}
func (j *MemoryRunJournal) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit int) ([]RunEvent, error) {
	if err := validateRunJournalOperation(ctx, j, scope); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxRunJournalReadLimit {
		return nil, ErrInvalidRunJournalReadLimit
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	events := j.streams[scope.Identity()]
	if after >= uint64(len(events)) {
		return []RunEvent{}, nil
	}
	start := int(after)
	end := min(start+limit, len(events))
	return append([]RunEvent(nil), events[start:end]...), nil
}
func validateRunJournalOperation(ctx context.Context, j *MemoryRunJournal, scope audit.ReviewScope) error {
	if isNilRunJournalContext(ctx) {
		return ErrInvalidRunJournalContext
	}
	if j == nil {
		return ErrInvalidRunJournal
	}
	if err := ctx.Err(); err != nil {
		return ErrRunJournalContextDone
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	return nil
}
func isNilRunJournalContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func validRunPlanQuery(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
