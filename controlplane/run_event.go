package controlplane

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxRunEventUnixMilliseconds = int64(253_402_300_799_999)

var (
	// ErrInvalidRunEventKind identifies an unknown orchestration transition.
	ErrInvalidRunEventKind = errors.New("invalid run event kind")
	// ErrInvalidRunEventSequence identifies a zero or inconsistent sequence.
	ErrInvalidRunEventSequence = errors.New("invalid run event sequence")
	// ErrInvalidRunEventPreviousIdentity identifies a malformed chain predecessor.
	ErrInvalidRunEventPreviousIdentity = errors.New("invalid run event previous identity")
	// ErrInvalidRunEventTask identifies a malformed or unexpected task reference.
	ErrInvalidRunEventTask = errors.New("invalid run event task")
	// ErrInvalidRunEventAttempt identifies an attempt outside closed event semantics.
	ErrInvalidRunEventAttempt = errors.New("invalid run event attempt")
	// ErrInvalidRunEventLease identifies malformed lease ownership or expiry.
	ErrInvalidRunEventLease = errors.New("invalid run event lease")
	// ErrInvalidRunEventOutput identifies a malformed or unexpected output identity.
	ErrInvalidRunEventOutput = errors.New("invalid run event output")
	// ErrInvalidRunEventFailure identifies an unknown or unexpected failure class.
	ErrInvalidRunEventFailure = errors.New("invalid run event failure")
	// ErrInvalidRunEventTime identifies a missing, excessive, or inconsistent time.
	ErrInvalidRunEventTime = errors.New("invalid run event time")
	// ErrInvalidRunEventIdentity identifies event content inconsistent with its identity.
	ErrInvalidRunEventIdentity = errors.New("invalid run event identity")
)

// RunEventKind identifies one append-only orchestration transition.
type RunEventKind uint8

const (
	RunEventOpened RunEventKind = iota + 1
	RunEventTaskAvailable
	RunEventTaskLeased
	RunEventTaskLeaseRenewed
	RunEventTaskSucceeded
	RunEventTaskFailed
	RunEventTaskSkipped
	RunEventSucceeded
	RunEventFailed
	RunEventCanceled
)

func (k RunEventKind) String() string {
	switch k {
	case RunEventOpened:
		return "run_opened"
	case RunEventTaskAvailable:
		return "task_available"
	case RunEventTaskLeased:
		return "task_leased"
	case RunEventTaskLeaseRenewed:
		return "task_lease_renewed"
	case RunEventTaskSucceeded:
		return "task_succeeded"
	case RunEventTaskFailed:
		return "task_failed"
	case RunEventTaskSkipped:
		return "task_skipped"
	case RunEventSucceeded:
		return "run_succeeded"
	case RunEventFailed:
		return "run_failed"
	case RunEventCanceled:
		return "run_canceled"
	default:
		return ""
	}
}
func (k RunEventKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidRunEventKind
	}
	return nil
}

// RunFailure is a closed, provider-neutral orchestration failure class.
type RunFailure uint8

const (
	RunFailureTransient RunFailure = iota + 1
	RunFailureResourceLimit
	RunFailurePolicy
	RunFailureInvalidInput
	RunFailureCanceled
	RunFailureDependency
	RunFailureInternal
)

func (f RunFailure) String() string {
	switch f {
	case RunFailureTransient:
		return "transient"
	case RunFailureResourceLimit:
		return "resource_limit"
	case RunFailurePolicy:
		return "policy"
	case RunFailureInvalidInput:
		return "invalid_input"
	case RunFailureCanceled:
		return "canceled"
	case RunFailureDependency:
		return "dependency"
	case RunFailureInternal:
		return "internal"
	default:
		return ""
	}
}
func (f RunFailure) Retryable() bool {
	return f == RunFailureTransient || f == RunFailureResourceLimit || f == RunFailureInternal
}

// RunEvent is one content-addressed member of a review run journal.
type RunEvent struct {
	identity             string
	planIdentity         string
	scope                audit.ReviewScope
	sequence             uint64
	previousIdentity     string
	kind                 RunEventKind
	taskKey              string
	taskIdentity         string
	attempt              uint8
	leaseTokenIdentity   string
	workerIdentity       string
	leaseExpiresAtMillis int64
	outputIdentity       string
	failure              RunFailure
	retryAtMillis        int64
	occurredAtMillis     int64
}

// NewRunEvent creates one structurally closed journal event.
func NewRunEvent(
	plan ReviewRunPlan,
	sequence uint64,
	previousIdentity string,
	kind RunEventKind,
	task TaskDefinition,
	attempt uint8,
	leaseTokenIdentity string,
	workerIdentity string,
	leaseExpiresAt time.Time,
	outputIdentity string,
	failure RunFailure,
	retryAt time.Time,
	occurredAt time.Time,
) (RunEvent, error) {
	if err := plan.Validate(); err != nil {
		return RunEvent{}, err
	}
	if err := kind.Validate(); err != nil {
		return RunEvent{}, err
	}
	if sequence == 0 {
		return RunEvent{}, ErrInvalidRunEventSequence
	}
	if sequence == 1 && previousIdentity != "" || sequence > 1 && !validControlPlaneDigest(previousIdentity) {
		return RunEvent{}, ErrInvalidRunEventPreviousIdentity
	}
	event := RunEvent{
		planIdentity: plan.Identity(), scope: plan.Scope(), sequence: sequence,
		previousIdentity: previousIdentity, kind: kind, attempt: attempt,
		leaseTokenIdentity: leaseTokenIdentity, workerIdentity: strings.Clone(workerIdentity),
		leaseExpiresAtMillis: timeToRunMillis(leaseExpiresAt), outputIdentity: outputIdentity,
		failure: failure, retryAtMillis: timeToRunMillis(retryAt), occurredAtMillis: timeToRunMillis(occurredAt),
	}
	if task.Identity() != "" {
		canonical, exists := plan.Task(task.Key())
		if !exists || canonical.Identity() != task.Identity() {
			return RunEvent{}, ErrInvalidRunEventTask
		}
		event.taskKey = task.Key()
		event.taskIdentity = task.Identity()
	}
	if err := event.validateFields(); err != nil {
		return RunEvent{}, err
	}
	event.identity = deriveRunEventIdentity(event)
	return event, nil
}

func (e RunEvent) Identity() string           { return e.identity }
func (e RunEvent) PlanIdentity() string       { return e.planIdentity }
func (e RunEvent) Scope() audit.ReviewScope   { return e.scope }
func (e RunEvent) Sequence() uint64           { return e.sequence }
func (e RunEvent) PreviousIdentity() string   { return e.previousIdentity }
func (e RunEvent) Kind() RunEventKind         { return e.kind }
func (e RunEvent) TaskKey() string            { return e.taskKey }
func (e RunEvent) TaskIdentity() string       { return e.taskIdentity }
func (e RunEvent) Attempt() uint8             { return e.attempt }
func (e RunEvent) LeaseTokenIdentity() string { return e.leaseTokenIdentity }
func (e RunEvent) WorkerIdentity() string     { return e.workerIdentity }
func (e RunEvent) LeaseExpiresAt() time.Time  { return runMillisToTime(e.leaseExpiresAtMillis) }
func (e RunEvent) OutputIdentity() string     { return e.outputIdentity }
func (e RunEvent) Failure() RunFailure        { return e.failure }
func (e RunEvent) RetryAt() time.Time         { return runMillisToTime(e.retryAtMillis) }
func (e RunEvent) OccurredAt() time.Time      { return runMillisToTime(e.occurredAtMillis) }
func (e RunEvent) String() string             { return "review run event" }
func (e RunEvent) GoString() string           { return "controlplane.RunEvent{<redacted>}" }
func (e RunEvent) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review run event", "controlplane.RunEvent{<redacted>}")
}
func (e RunEvent) Validate() error {
	if err := e.scope.Validate(); err != nil {
		return err
	}
	if !validControlPlaneDigest(e.planIdentity) || e.sequence == 0 {
		return ErrInvalidRunEventSequence
	}
	if e.sequence == 1 && e.previousIdentity != "" || e.sequence > 1 && !validControlPlaneDigest(e.previousIdentity) {
		return ErrInvalidRunEventPreviousIdentity
	}
	if err := e.kind.Validate(); err != nil {
		return err
	}
	if err := e.validateFields(); err != nil {
		return err
	}
	if e.identity != deriveRunEventIdentity(e) {
		return ErrInvalidRunEventIdentity
	}
	return nil
}

func (e RunEvent) validateFields() error {
	if !validRunMillis(e.occurredAtMillis) {
		return ErrInvalidRunEventTime
	}
	hasTask := e.taskKey != "" || e.taskIdentity != ""
	if hasTask && (!validReviewTaskKey(e.taskKey) || !validControlPlaneDigest(e.taskIdentity)) {
		return ErrInvalidRunEventTask
	}
	switch e.kind {
	case RunEventOpened:
		if hasTask || e.hasAttemptFields() || e.outputIdentity != "" || e.failure != 0 || e.retryAtMillis != 0 {
			return ErrInvalidRunEventTask
		}
	case RunEventTaskAvailable:
		if !hasTask || e.hasAttemptFields() || e.outputIdentity != "" || e.failure != 0 || e.retryAtMillis != 0 {
			return ErrInvalidRunEventTask
		}
	case RunEventTaskLeased, RunEventTaskLeaseRenewed:
		validLease := e.attempt != 0 && validControlPlaneDigest(e.leaseTokenIdentity)
		validOwner := validWorkerIdentity(e.workerIdentity)
		validExpiry := e.leaseExpiresAtMillis > e.occurredAtMillis
		emptyResult := e.outputIdentity == "" && e.failure == 0 && e.retryAtMillis == 0
		if !hasTask || !validLease || !validOwner || !validExpiry || !emptyResult {
			return ErrInvalidRunEventLease
		}
	case RunEventTaskSucceeded:
		validLease := e.attempt != 0 && validControlPlaneDigest(e.leaseTokenIdentity)
		emptyLeaseMetadata := e.workerIdentity == "" && e.leaseExpiresAtMillis == 0
		validResult := validControlPlaneDigest(e.outputIdentity) && e.failure == 0 && e.retryAtMillis == 0
		if !hasTask || !validLease || !emptyLeaseMetadata || !validResult {
			return ErrInvalidRunEventOutput
		}
	case RunEventTaskFailed:
		if !hasTask || e.attempt == 0 || !validControlPlaneDigest(e.leaseTokenIdentity) || e.workerIdentity != "" || e.leaseExpiresAtMillis != 0 || e.outputIdentity != "" || e.failure.String() == "" {
			return ErrInvalidRunEventFailure
		}
		if e.retryAtMillis != 0 && (!e.failure.Retryable() || e.retryAtMillis < e.occurredAtMillis) {
			return ErrInvalidRunEventTime
		}
	case RunEventTaskSkipped:
		if !hasTask || e.hasAttemptFields() || e.outputIdentity != "" || (e.failure != RunFailureDependency && e.failure != RunFailurePolicy) || e.retryAtMillis != 0 {
			return ErrInvalidRunEventFailure
		}
	case RunEventSucceeded:
		if hasTask || e.hasAttemptFields() || !validControlPlaneDigest(e.outputIdentity) || e.failure != 0 || e.retryAtMillis != 0 {
			return ErrInvalidRunEventOutput
		}
	case RunEventFailed:
		if hasTask || e.hasAttemptFields() || e.outputIdentity != "" || e.failure.String() == "" || e.retryAtMillis != 0 {
			return ErrInvalidRunEventFailure
		}
	case RunEventCanceled:
		if hasTask || e.hasAttemptFields() || e.outputIdentity != "" || e.failure != RunFailureCanceled || e.retryAtMillis != 0 {
			return ErrInvalidRunEventFailure
		}
	}
	return nil
}
func (e RunEvent) hasAttemptFields() bool {
	return e.attempt != 0 || e.leaseTokenIdentity != "" || e.workerIdentity != "" || e.leaseExpiresAtMillis != 0
}
func validWorkerIdentity(value string) bool {
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
func validRunMillis(value int64) bool { return value > 0 && value <= maxRunEventUnixMilliseconds }
func timeToRunMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}
func runMillisToTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}
func deriveRunEventIdentity(event RunEvent) string {
	preimage := struct {
		Contract     string `json:"contract"`
		Version      int    `json:"version"`
		Plan         string `json:"plan"`
		Scope        string `json:"scope"`
		Sequence     uint64 `json:"sequence"`
		Previous     string `json:"previous"`
		Kind         string `json:"kind"`
		TaskKey      string `json:"task_key"`
		Task         string `json:"task"`
		Attempt      uint8  `json:"attempt"`
		LeaseToken   string `json:"lease_token"`
		Worker       string `json:"worker"`
		LeaseExpires int64  `json:"lease_expires"`
		Output       string `json:"output"`
		Failure      string `json:"failure"`
		RetryAt      int64  `json:"retry_at"`
		OccurredAt   int64  `json:"occurred_at"`
	}{
		Contract: "open-trestle/review-run-event", Version: 1,
		Plan: event.planIdentity, Scope: event.scope.Identity(), Sequence: event.sequence,
		Previous: event.previousIdentity, Kind: event.kind.String(),
		TaskKey: event.taskKey, Task: event.taskIdentity, Attempt: event.attempt,
		LeaseToken: event.leaseTokenIdentity, Worker: event.workerIdentity,
		LeaseExpires: event.leaseExpiresAtMillis, Output: event.outputIdentity,
		Failure: event.failure.String(), RetryAt: event.retryAtMillis, OccurredAt: event.occurredAtMillis,
	}
	return hashControlPlaneValue(preimage)
}
