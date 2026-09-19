package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maximumTaskNotificationDeliveries = 10
	minimumTaskNotificationLease      = time.Second
	maximumTaskNotificationLease      = 24 * time.Hour
)

var (
	ErrInvalidTaskNotification         = errors.New("invalid task notification")
	ErrInvalidTaskNotificationEncoding = errors.New("invalid task notification encoding")
	ErrInvalidTaskNotificationQueue    = errors.New("invalid task notification queue")
	ErrTaskNotificationConflict        = errors.New("task notification conflict")
	ErrTaskNotificationLeaseMismatch   = errors.New("task notification lease mismatch")
	ErrTaskNotificationWaitCanceled    = errors.New("task notification wait canceled")
)

// TaskNotification is a content-free, non-authoritative hint about claimable work.
type TaskNotification struct {
	identity                                                       string
	scope                                                          audit.ReviewScope
	planIdentity                                                   string
	taskStateRevision                                              uint64
	taskStateEventIdentity, taskKey, taskIdentity, handlerIdentity string
	attempt                                                        uint8
	availableAtMillis                                              int64
}

// NewTaskNotification derives a stable hint from one replayed authoritative state.
func NewTaskNotification(state ReviewRunState, runtime TaskRuntimeState, at time.Time) (TaskNotification, error) {
	if state.Validate() != nil || runtime.definition.Validate() != nil || state.Status() != ReviewRunActive || !transitionTimeAllowed(state, at) {
		return TaskNotification{}, ErrInvalidTaskNotification
	}
	current, ok := state.Task(runtime.Key())
	if !ok || !sameTaskNotificationRuntime(current, runtime) {
		return TaskNotification{}, ErrInvalidTaskNotification
	}
	availableAt := runtime.LastEventAt()
	eligible := runtime.status == TaskRuntimeAvailable
	if runtime.status == TaskRuntimeLeased && runtime.LeaseExpiresAt().UnixMilli() > 0 && at.UnixMilli() >= runtime.LeaseExpiresAt().UnixMilli() {
		eligible = true
		availableAt = runtime.LeaseExpiresAt()
	}
	attempt := runtime.attempts + 1
	if !eligible || attempt == 0 || attempt > runtime.definition.MaxAttempts() || availableAt.IsZero() || availableAt.After(at) {
		return TaskNotification{}, ErrInvalidTaskNotification
	}
	n := TaskNotification{scope: state.plan.Scope(), planIdentity: state.plan.Identity(), taskStateRevision: runtime.lastEventRevision, taskStateEventIdentity: runtime.lastEventIdentity, taskKey: runtime.Key(), taskIdentity: runtime.definition.Identity(), handlerIdentity: runtime.definition.HandlerIdentity(), attempt: attempt, availableAtMillis: availableAt.UnixMilli()}
	n.identity = deriveTaskNotificationIdentity(n)
	if n.Validate() != nil {
		return TaskNotification{}, ErrInvalidTaskNotification
	}
	return n, nil
}
func sameTaskNotificationRuntime(first, second TaskRuntimeState) bool {
	return first.definition.Identity() == second.definition.Identity() && first.status == second.status && first.attempts == second.attempts && first.leaseTokenIdentity == second.leaseTokenIdentity && first.workerIdentity == second.workerIdentity && first.leaseExpiresAtMillis == second.leaseExpiresAtMillis && first.outputIdentity == second.outputIdentity && first.failure == second.failure && first.retryAtMillis == second.retryAtMillis && first.lastEventRevision == second.lastEventRevision && first.lastEventIdentity == second.lastEventIdentity && first.lastEventAtMillis == second.lastEventAtMillis
}

func (n TaskNotification) Identity() string               { return n.identity }
func (n TaskNotification) Scope() audit.ReviewScope       { return n.scope }
func (n TaskNotification) PlanIdentity() string           { return n.planIdentity }
func (n TaskNotification) TaskStateRevision() uint64      { return n.taskStateRevision }
func (n TaskNotification) TaskStateEventIdentity() string { return n.taskStateEventIdentity }
func (n TaskNotification) TaskKey() string                { return n.taskKey }
func (n TaskNotification) TaskIdentity() string           { return n.taskIdentity }
func (n TaskNotification) HandlerIdentity() string        { return n.handlerIdentity }
func (n TaskNotification) Attempt() uint8                 { return n.attempt }
func (n TaskNotification) AvailableAt() time.Time         { return runMillisToTime(n.availableAtMillis) }
func (n TaskNotification) Validate() error {
	if n.scope.Validate() != nil || !validControlPlaneDigest(n.planIdentity) || n.taskStateRevision == 0 || n.taskStateRevision > maxRunJournalStreamEvents || !validControlPlaneDigest(n.taskStateEventIdentity) || !validReviewTaskKey(n.taskKey) || !validControlPlaneDigest(n.taskIdentity) || !validControlPlaneDigest(n.handlerIdentity) || n.attempt == 0 || !validRunMillis(n.availableAtMillis) || n.identity != deriveTaskNotificationIdentity(n) {
		return ErrInvalidTaskNotification
	}
	return nil
}
func (n TaskNotification) String() string   { return "task notification" }
func (n TaskNotification) GoString() string { return "controlplane.TaskNotification{<redacted>}" }
func (n TaskNotification) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task notification", "controlplane.TaskNotification{<redacted>}")
}
func deriveTaskNotificationIdentity(n TaskNotification) string {
	return hashControlPlaneValue(struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		ScopeIdentity           string `json:"scope_identity"`
		PlanIdentity            string `json:"plan_identity"`
		TaskStateRevision       uint64 `json:"task_state_revision"`
		TaskStateEventIdentity  string `json:"task_state_event_identity"`
		TaskKey                 string `json:"task_key"`
		TaskIdentity            string `json:"task_identity"`
		HandlerIdentity         string `json:"handler_identity"`
		Attempt                 uint8  `json:"attempt"`
		AvailableAtMilliseconds int64  `json:"available_at_milliseconds"`
	}{"open-trestle/task-notification-identity", 1, n.scope.Identity(), n.planIdentity, n.taskStateRevision, n.taskStateEventIdentity, n.taskKey, n.taskIdentity, n.handlerIdentity, n.attempt, n.availableAtMillis})
}

// TaskNotificationLease is a secret-bearing delivery capability, not task authority.
type TaskNotificationLease struct {
	identity                             string
	notification                         TaskNotification
	workerIdentity, token, tokenIdentity string
	delivery                             uint8
	leasedAtMillis, expiresAtMillis      int64
}

// NewTaskNotificationLease validates one queue-issued delivery capability.
func NewTaskNotificationLease(notification TaskNotification, workerIdentity, token string, delivery uint8, leasedAt, expiresAt time.Time) (TaskNotificationLease, error) {
	l := TaskNotificationLease{notification: notification, workerIdentity: workerIdentity, token: token, tokenIdentity: deriveTaskNotificationTokenIdentity(token), delivery: delivery, leasedAtMillis: leasedAt.UnixMilli(), expiresAtMillis: expiresAt.UnixMilli()}
	l.identity = deriveTaskNotificationLeaseIdentity(l)
	if l.Validate() != nil {
		return TaskNotificationLease{}, ErrTaskNotificationLeaseMismatch
	}
	return l, nil
}
func (l TaskNotificationLease) Identity() string               { return l.identity }
func (l TaskNotificationLease) Notification() TaskNotification { return l.notification }
func (l TaskNotificationLease) WorkerIdentity() string         { return l.workerIdentity }
func (l TaskNotificationLease) TokenIdentity() string          { return l.tokenIdentity }
func (l TaskNotificationLease) Delivery() uint8                { return l.delivery }
func (l TaskNotificationLease) LeasedAt() time.Time            { return runMillisToTime(l.leasedAtMillis) }
func (l TaskNotificationLease) ExpiresAt() time.Time           { return runMillisToTime(l.expiresAtMillis) }
func (l TaskNotificationLease) Validate() error {
	durationMillis := l.expiresAtMillis - l.leasedAtMillis
	if l.notification.Validate() != nil || !validWorkerIdentity(l.workerIdentity) || !validLeaseToken(l.token) || deriveTaskNotificationTokenIdentity(l.token) != l.tokenIdentity || l.delivery == 0 || l.delivery > maximumTaskNotificationDeliveries || !validRunMillis(l.leasedAtMillis) || !validRunMillis(l.expiresAtMillis) || l.leasedAtMillis < l.notification.availableAtMillis || l.expiresAtMillis <= l.leasedAtMillis || durationMillis < minimumTaskNotificationLease.Milliseconds() || durationMillis > maximumTaskNotificationLease.Milliseconds() || l.identity != deriveTaskNotificationLeaseIdentity(l) {
		return ErrTaskNotificationLeaseMismatch
	}
	return nil
}
func (l TaskNotificationLease) String() string { return "task notification lease" }
func (l TaskNotificationLease) GoString() string {
	return "controlplane.TaskNotificationLease{<redacted>}"
}
func (l TaskNotificationLease) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task notification lease", "controlplane.TaskNotificationLease{<redacted>}")
}
func deriveTaskNotificationLeaseIdentity(l TaskNotificationLease) string {
	return hashControlPlaneValue(struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		NotificationIdentity  string `json:"notification_identity"`
		WorkerIdentity        string `json:"worker_identity"`
		TokenIdentity         string `json:"token_identity"`
		Delivery              uint8  `json:"delivery"`
		LeasedAtMilliseconds  int64  `json:"leased_at_milliseconds"`
		ExpiresAtMilliseconds int64  `json:"expires_at_milliseconds"`
	}{"open-trestle/task-notification-lease-identity", 1, l.notification.Identity(), l.workerIdentity, l.tokenIdentity, l.delivery, l.leasedAtMillis, l.expiresAtMillis})
}
func deriveTaskNotificationTokenIdentity(token string) string {
	return hashControlPlaneValue(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Token         string `json:"token"`
	}{"open-trestle/task-notification-token", 1, token})
}

// TaskNotificationQueue durably leases non-authoritative scheduling hints.
type TaskNotificationQueue interface {
	EnqueueTaskNotification(context.Context, TaskNotification) (bool, error)
	ClaimTaskNotification(context.Context, audit.ReviewScope, string, time.Time, time.Duration) (TaskNotificationLease, bool, error)
	AcknowledgeTaskNotification(context.Context, TaskNotificationLease, time.Time) error
}

// TaskNotificationWaiter blocks until a queue receives a distributed wake-up.
type TaskNotificationWaiter interface{ WaitForTaskNotification(context.Context) error }

type memoryTaskNotificationItem struct {
	notification          TaskNotification
	delivery              uint8
	worker, tokenIdentity string
	leaseExpires          int64
	acknowledged          bool
}

// MemoryTaskNotificationQueue is a concurrency-safe queue for local operation and tests.
type MemoryTaskNotificationQueue struct {
	mu     sync.Mutex
	random io.Reader
	items  map[string]memoryTaskNotificationItem
	wake   chan struct{}
}

func NewMemoryTaskNotificationQueue() *MemoryTaskNotificationQueue {
	return newMemoryTaskNotificationQueue(nil)
}
func newMemoryTaskNotificationQueue(random io.Reader) *MemoryTaskNotificationQueue {
	if random == nil {
		random = defaultNotificationRandom{}
	}
	return &MemoryTaskNotificationQueue{random: random, items: make(map[string]memoryTaskNotificationItem), wake: make(chan struct{}, 1)}
}
func (q *MemoryTaskNotificationQueue) EnqueueTaskNotification(ctx context.Context, n TaskNotification) (bool, error) {
	if invalidNotificationOperation(ctx, q) || n.Validate() != nil {
		return false, ErrInvalidTaskNotificationQueue
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if existing, ok := q.items[n.Identity()]; ok {
		if existing.notification.Identity() != n.Identity() {
			return false, ErrTaskNotificationConflict
		}
		return false, nil
	}
	q.items[n.Identity()] = memoryTaskNotificationItem{notification: n}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true, nil
}
func (q *MemoryTaskNotificationQueue) ClaimTaskNotification(ctx context.Context, scope audit.ReviewScope, worker string, at time.Time, duration time.Duration) (TaskNotificationLease, bool, error) {
	if invalidNotificationOperation(ctx, q) || scope.Validate() != nil || !validWorkerIdentity(worker) || !validNotificationClaimTime(at, duration) {
		return TaskNotificationLease{}, false, ErrInvalidTaskNotificationQueue
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	identities := make([]string, 0)
	for identity, item := range q.items {
		if item.notification.Scope().Identity() == scope.Identity() && !item.acknowledged && item.delivery < maximumTaskNotificationDeliveries && item.notification.availableAtMillis <= at.UnixMilli() && (item.leaseExpires == 0 || item.leaseExpires <= at.UnixMilli()) {
			identities = append(identities, identity)
		}
	}
	sort.Slice(identities, func(i, j int) bool {
		a, b := q.items[identities[i]].notification, q.items[identities[j]].notification
		if a.availableAtMillis != b.availableAtMillis {
			return a.availableAtMillis < b.availableAtMillis
		}
		return identities[i] < identities[j]
	})
	if len(identities) == 0 {
		return TaskNotificationLease{}, false, nil
	}
	token, err := newNotificationToken(q.random)
	if err != nil {
		return TaskNotificationLease{}, false, ErrInvalidTaskNotificationQueue
	}
	item := q.items[identities[0]]
	if item.tokenIdentity != "" && deriveTaskNotificationTokenIdentity(token) == item.tokenIdentity {
		return TaskNotificationLease{}, false, ErrInvalidTaskNotificationQueue
	}
	item.delivery++
	expires := at.Add(duration)
	lease, err := NewTaskNotificationLease(item.notification, worker, token, item.delivery, at, expires)
	if err != nil {
		return TaskNotificationLease{}, false, ErrInvalidTaskNotificationQueue
	}
	item.worker = worker
	item.tokenIdentity = lease.TokenIdentity()
	item.leaseExpires = expires.UnixMilli()
	q.items[identities[0]] = item
	return lease, true, nil
}
func (q *MemoryTaskNotificationQueue) AcknowledgeTaskNotification(ctx context.Context, lease TaskNotificationLease, at time.Time) error {
	if invalidNotificationOperation(ctx, q) || lease.Validate() != nil || !validRunMillis(at.UnixMilli()) {
		return ErrInvalidTaskNotificationQueue
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	item, ok := q.items[lease.Notification().Identity()]
	if !ok || item.acknowledged || item.delivery != lease.delivery || item.worker != lease.workerIdentity || item.tokenIdentity != lease.tokenIdentity || item.leaseExpires != lease.expiresAtMillis || at.UnixMilli() < lease.leasedAtMillis || at.UnixMilli() > item.leaseExpires {
		return ErrTaskNotificationLeaseMismatch
	}
	item.acknowledged = true
	item.worker = ""
	item.tokenIdentity = ""
	item.leaseExpires = 0
	q.items[lease.Notification().Identity()] = item
	return nil
}
func (q *MemoryTaskNotificationQueue) WaitForTaskNotification(ctx context.Context) error {
	if q == nil || q.random == nil || q.wake == nil || ctx == nil {
		return ErrInvalidTaskNotificationQueue
	}
	if ctx.Err() != nil {
		return ErrTaskNotificationWaitCanceled
	}
	select {
	case <-ctx.Done():
		return ErrTaskNotificationWaitCanceled
	case <-q.wake:
		return nil
	}
}

func invalidNotificationOperation(ctx context.Context, q *MemoryTaskNotificationQueue) bool {
	return q == nil || q.random == nil || ctx == nil || ctx.Err() != nil
}
func validNotificationClaimTime(at time.Time, duration time.Duration) bool {
	return validRunMillis(at.UnixMilli()) && duration%time.Millisecond == 0 && duration >= minimumTaskNotificationLease && duration <= maximumTaskNotificationLease && at.Add(duration).After(at) && validRunMillis(at.Add(duration).UnixMilli())
}

type defaultNotificationRandom struct{}

func (defaultNotificationRandom) Read(p []byte) (int, error) { return rand.Read(p) }
func newNotificationToken(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	token := hex.EncodeToString(value)
	if !validLeaseToken(token) {
		return "", ErrInvalidTaskNotificationQueue
	}
	return token, nil
}

// TaskNotificationScheduler derives queue hints only from replayed journal state.
type TaskNotificationScheduler struct {
	journal     RunJournal
	coordinator *Coordinator
	queue       TaskNotificationQueue
}

func NewTaskNotificationScheduler(journal RunJournal, queue TaskNotificationQueue) (*TaskNotificationScheduler, error) {
	if isNilRunJournal(journal) || isNilTaskNotificationQueue(queue) {
		return nil, ErrInvalidTaskNotificationQueue
	}
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidTaskNotificationQueue
	}
	return &TaskNotificationScheduler{journal: journal, coordinator: coordinator, queue: queue}, nil
}
func (s *TaskNotificationScheduler) ReconcileRun(ctx context.Context, scope audit.ReviewScope, at time.Time) (ReviewRunState, int, error) {
	if s == nil || isNilRunJournal(s.journal) || s.coordinator == nil || isNilTaskNotificationQueue(s.queue) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil {
		return ReviewRunState{}, 0, ErrInvalidTaskNotificationQueue
	}
	plan, state, err := s.coordinator.Resume(ctx, scope)
	if err != nil {
		return ReviewRunState{}, 0, err
	}
	if state.Status() != ReviewRunActive {
		return state, 0, nil
	}
	state, err = s.coordinator.Advance(ctx, plan, at)
	if err != nil {
		return ReviewRunState{}, 0, err
	}
	count := 0
	for _, definition := range plan.Tasks() {
		runtime, _ := state.Task(definition.Key())
		notice, noticeErr := NewTaskNotification(state, runtime, at)
		if noticeErr != nil {
			continue
		}
		created, enqueueErr := s.queue.EnqueueTaskNotification(ctx, notice)
		if enqueueErr != nil {
			return ReviewRunState{}, count, enqueueErr
		}
		if created {
			count++
		}
	}
	return state, count, nil
}

// ReconcileRepository scans a bounded tenant and repository plan partition.
func (s *TaskNotificationScheduler) ReconcileRepository(ctx context.Context, tenantID, repositoryID string, at time.Time) (int, int, error) {
	if s == nil || isNilRunJournal(s.journal) || s.coordinator == nil || isNilTaskNotificationQueue(s.queue) || ctx == nil || ctx.Err() != nil || !validRunPlanQuery(tenantID) || !validRunPlanQuery(repositoryID) || !validRunMillis(at.UnixMilli()) {
		return 0, 0, ErrInvalidTaskNotificationQueue
	}
	const pageSize = 100
	const maximumRuns = 10_000
	after := ""
	runs, notices := 0, 0
	for {
		plans, err := s.journal.ListPlans(ctx, tenantID, repositoryID, after, pageSize)
		if err != nil {
			return runs, notices, err
		}
		for _, plan := range plans {
			if runs >= maximumRuns {
				return runs, notices, ErrInvalidTaskNotificationQueue
			}
			_, created, err := s.ReconcileRun(ctx, plan.Scope(), at)
			if err != nil {
				return runs, notices, err
			}
			runs++
			notices += created
		}
		if len(plans) < pageSize {
			return runs, notices, nil
		}
		after = plans[len(plans)-1].Scope().ReviewRunID()
	}
}

func isNilTaskNotificationQueue(queue TaskNotificationQueue) bool {
	if queue == nil {
		return true
	}
	value := reflect.ValueOf(queue)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

var _ TaskNotificationWaiter = (*MemoryTaskNotificationQueue)(nil)
