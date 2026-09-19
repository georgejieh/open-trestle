package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxEncodedReviewRunReceiptBytes = 256 << 10

var (
	// ErrInvalidReviewRunReceipt identifies malformed or inconsistent public state.
	ErrInvalidReviewRunReceipt = errors.New("invalid review run receipt")
	// ErrInvalidReviewRunReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidReviewRunReceiptIdentity = errors.New("invalid review run receipt identity")
	// ErrInvalidReviewRunReceiptEncoding identifies noncanonical, unknown, or excessive JSON.
	ErrInvalidReviewRunReceiptEncoding = errors.New("invalid review run receipt encoding")
)

// ReviewTaskReceipt is secret-free public state for one task.
type ReviewTaskReceipt struct {
	key, taskIdentity, inputIdentity, handlerIdentity string
	kind                                              TaskKind
	required                                          bool
	status                                            TaskRuntimeStatus
	attempts, maxAttempts                             uint8
	leaseExpiresAtMillis                              int64
	outputIdentity                                    string
	failure                                           RunFailure
	retryAtMillis                                     int64
}

func (r ReviewTaskReceipt) Key() string               { return r.key }
func (r ReviewTaskReceipt) TaskIdentity() string      { return r.taskIdentity }
func (r ReviewTaskReceipt) InputIdentity() string     { return r.inputIdentity }
func (r ReviewTaskReceipt) HandlerIdentity() string   { return r.handlerIdentity }
func (r ReviewTaskReceipt) Kind() TaskKind            { return r.kind }
func (r ReviewTaskReceipt) Required() bool            { return r.required }
func (r ReviewTaskReceipt) Status() TaskRuntimeStatus { return r.status }
func (r ReviewTaskReceipt) Attempts() uint8           { return r.attempts }
func (r ReviewTaskReceipt) MaxAttempts() uint8        { return r.maxAttempts }
func (r ReviewTaskReceipt) LeaseExpiresAt() time.Time { return runMillisToTime(r.leaseExpiresAtMillis) }
func (r ReviewTaskReceipt) OutputIdentity() string    { return r.outputIdentity }
func (r ReviewTaskReceipt) Failure() RunFailure       { return r.failure }
func (r ReviewTaskReceipt) RetryAt() time.Time        { return runMillisToTime(r.retryAtMillis) }
func (r ReviewTaskReceipt) Validate() error {
	validKey := validReviewTaskKey(r.key)
	validIdentities := validControlPlaneDigest(r.taskIdentity) && validControlPlaneDigest(r.inputIdentity) && validControlPlaneDigest(r.handlerIdentity)
	validKinds := r.kind.Validate() == nil && r.status.String() != ""
	validAttempts := r.maxAttempts > 0 && r.maxAttempts <= maxReviewTaskAttempts && r.attempts <= r.maxAttempts
	if !validKey || !validIdentities || !validKinds || !validAttempts {
		return ErrInvalidReviewRunReceipt
	}
	switch r.status {
	case TaskRuntimePending:
		if r.attempts != 0 || r.hasResultFields() {
			return ErrInvalidReviewRunReceipt
		}
	case TaskRuntimeAvailable:
		if r.leaseExpiresAtMillis != 0 || r.outputIdentity != "" || r.failure != 0 || r.retryAtMillis != 0 {
			return ErrInvalidReviewRunReceipt
		}
	case TaskRuntimeLeased:
		if r.attempts == 0 || !validRunMillis(r.leaseExpiresAtMillis) || r.outputIdentity != "" || r.failure != 0 || r.retryAtMillis != 0 {
			return ErrInvalidReviewRunReceipt
		}
	case TaskRuntimeSucceeded:
		if r.attempts == 0 || r.leaseExpiresAtMillis != 0 || !validControlPlaneDigest(r.outputIdentity) || r.failure != 0 || r.retryAtMillis != 0 {
			return ErrInvalidReviewRunReceipt
		}
	case TaskRuntimeFailed:
		if r.attempts == 0 || r.leaseExpiresAtMillis != 0 || r.outputIdentity != "" || r.failure.String() == "" {
			return ErrInvalidReviewRunReceipt
		}
		canRetry := r.failure.Retryable() && r.attempts < r.maxAttempts
		hasRetryTime := r.retryAtMillis != 0 && validRunMillis(r.retryAtMillis)
		if canRetry != hasRetryTime {
			return ErrInvalidReviewRunReceipt
		}
	case TaskRuntimeSkipped:
		if r.attempts != 0 || r.leaseExpiresAtMillis != 0 || r.outputIdentity != "" || (r.failure != RunFailureDependency && r.failure != RunFailurePolicy) || r.retryAtMillis != 0 {
			return ErrInvalidReviewRunReceipt
		}
	}
	return nil
}
func (r ReviewTaskReceipt) hasResultFields() bool {
	return r.leaseExpiresAtMillis != 0 || r.outputIdentity != "" || r.failure != 0 || r.retryAtMillis != 0
}
func (r ReviewTaskReceipt) String() string   { return "review task receipt" }
func (r ReviewTaskReceipt) GoString() string { return "controlplane.ReviewTaskReceipt{<redacted>}" }
func (r ReviewTaskReceipt) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review task receipt", "controlplane.ReviewTaskReceipt{<redacted>}")
}

// ReviewRunReceipt is content-addressed, secret-free state for clients and transports.
type ReviewRunReceipt struct {
	identity, planIdentity string
	scope                  audit.ReviewScope
	status                 ReviewRunStatus
	revision               uint64
	headIdentity           string
	lastOccurredAtMillis   int64
	outputIdentity         string
	failure                RunFailure
	tasks                  []ReviewTaskReceipt
}

func NewReviewRunReceipt(state ReviewRunState) (ReviewRunReceipt, error) {
	if err := state.Validate(); err != nil {
		return ReviewRunReceipt{}, err
	}
	tasks := make([]ReviewTaskReceipt, 0, state.Plan().TaskCount())
	for _, definition := range state.Plan().Tasks() {
		runtime, _ := state.Task(definition.Key())
		tasks = append(tasks, ReviewTaskReceipt{
			key: definition.Key(), taskIdentity: definition.Identity(),
			inputIdentity: definition.InputIdentity(), handlerIdentity: definition.HandlerIdentity(),
			kind: definition.Kind(), required: definition.Required(), status: runtime.Status(),
			attempts: runtime.Attempts(), maxAttempts: definition.MaxAttempts(),
			leaseExpiresAtMillis: runtime.leaseExpiresAtMillis, outputIdentity: runtime.OutputIdentity(),
			failure: runtime.Failure(), retryAtMillis: runtime.retryAtMillis,
		})
	}
	receipt := ReviewRunReceipt{
		planIdentity: state.Plan().Identity(), scope: state.Plan().Scope(), status: state.Status(),
		revision: state.Revision(), headIdentity: state.HeadIdentity(),
		lastOccurredAtMillis: state.lastOccurredAtMillis, outputIdentity: state.OutputIdentity(),
		failure: state.Failure(), tasks: tasks,
	}
	receipt.identity = deriveReviewRunReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return ReviewRunReceipt{}, err
	}
	return receipt, nil
}
func (r ReviewRunReceipt) Identity() string          { return r.identity }
func (r ReviewRunReceipt) PlanIdentity() string      { return r.planIdentity }
func (r ReviewRunReceipt) Scope() audit.ReviewScope  { return r.scope }
func (r ReviewRunReceipt) Status() ReviewRunStatus   { return r.status }
func (r ReviewRunReceipt) Revision() uint64          { return r.revision }
func (r ReviewRunReceipt) HeadIdentity() string      { return r.headIdentity }
func (r ReviewRunReceipt) LastOccurredAt() time.Time { return runMillisToTime(r.lastOccurredAtMillis) }
func (r ReviewRunReceipt) OutputIdentity() string    { return r.outputIdentity }
func (r ReviewRunReceipt) Failure() RunFailure       { return r.failure }
func (r ReviewRunReceipt) TaskCount() int            { return len(r.tasks) }
func (r ReviewRunReceipt) Tasks() []ReviewTaskReceipt {
	return append([]ReviewTaskReceipt(nil), r.tasks...)
}
func (r ReviewRunReceipt) Task(key string) (ReviewTaskReceipt, bool) {
	index := sort.Search(len(r.tasks), func(i int) bool { return r.tasks[i].Key() >= key })
	if index == len(r.tasks) || r.tasks[index].Key() != key {
		return ReviewTaskReceipt{}, false
	}
	return r.tasks[index], true
}
func (r ReviewRunReceipt) Validate() error {
	validHeader := validControlPlaneDigest(r.planIdentity) && r.scope.Validate() == nil && r.status.String() != ""
	validRevision := r.revision > 0 && validControlPlaneDigest(r.headIdentity) && validRunMillis(r.lastOccurredAtMillis)
	validTaskCount := len(r.tasks) > 0 && len(r.tasks) <= maxReviewRunTasks
	if !validHeader || !validRevision || !validTaskCount {
		return ErrInvalidReviewRunReceipt
	}
	previous := ""
	for _, task := range r.tasks {
		if task.Validate() != nil || task.Key() <= previous {
			return ErrInvalidReviewRunReceipt
		}
		previous = task.Key()
	}
	switch r.status {
	case ReviewRunActive:
		if r.outputIdentity != "" || r.failure != 0 {
			return ErrInvalidReviewRunReceipt
		}
	case ReviewRunSucceeded:
		if !validControlPlaneDigest(r.outputIdentity) || r.failure != 0 {
			return ErrInvalidReviewRunReceipt
		}
	case ReviewRunFailed:
		if r.outputIdentity != "" || r.failure.String() == "" {
			return ErrInvalidReviewRunReceipt
		}
	case ReviewRunCanceled:
		if r.outputIdentity != "" || r.failure != RunFailureCanceled {
			return ErrInvalidReviewRunReceipt
		}
	}
	if r.identity != deriveReviewRunReceiptIdentity(r) {
		return ErrInvalidReviewRunReceiptIdentity
	}
	return nil
}
func (r ReviewRunReceipt) String() string   { return "review run receipt" }
func (r ReviewRunReceipt) GoString() string { return "controlplane.ReviewRunReceipt{<redacted>}" }
func (r ReviewRunReceipt) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review run receipt", "controlplane.ReviewRunReceipt{<redacted>}")
}

type reviewTaskReceiptRecord struct {
	Key                        string `json:"key"`
	TaskIdentity               string `json:"task_identity"`
	InputIdentity              string `json:"input_identity"`
	HandlerIdentity            string `json:"handler_identity"`
	Kind                       string `json:"kind"`
	Required                   bool   `json:"required"`
	Status                     string `json:"status"`
	Attempts                   uint8  `json:"attempts"`
	MaxAttempts                uint8  `json:"max_attempts"`
	LeaseExpiresAtMilliseconds int64  `json:"lease_expires_at_milliseconds"`
	OutputIdentity             string `json:"output_identity"`
	Failure                    string `json:"failure"`
	RetryAtMilliseconds        int64  `json:"retry_at_milliseconds"`
}
type reviewRunReceiptRecord struct {
	Contract                   string                    `json:"contract"`
	SchemaVersion              int                       `json:"schema_version"`
	Identity                   string                    `json:"identity"`
	PlanIdentity               string                    `json:"plan_identity"`
	TenantID                   string                    `json:"tenant_id"`
	RepositoryID               string                    `json:"repository_id"`
	ReviewRunID                string                    `json:"review_run_id"`
	Status                     string                    `json:"status"`
	Revision                   uint64                    `json:"revision"`
	HeadIdentity               string                    `json:"head_identity"`
	LastOccurredAtMilliseconds int64                     `json:"last_occurred_at_milliseconds"`
	OutputIdentity             string                    `json:"output_identity"`
	Failure                    string                    `json:"failure"`
	Tasks                      []reviewTaskReceiptRecord `json:"tasks"`
}

func EncodeReviewRunReceipt(receipt ReviewRunReceipt) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(reviewRunReceiptToRecord(receipt))
	if err != nil || len(encoded) > maxEncodedReviewRunReceiptBytes {
		return nil, ErrInvalidReviewRunReceiptEncoding
	}
	return encoded, nil
}
func ParseReviewRunReceipt(encoded []byte) (ReviewRunReceipt, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedReviewRunReceiptBytes {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record reviewRunReceiptRecord
	if err := decoder.Decode(&record); err != nil {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/review-run-receipt" || record.SchemaVersion != 1 {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	status, err := parseReviewRunStatus(record.Status)
	if err != nil {
		return ReviewRunReceipt{}, err
	}
	failure, err := parseRunFailure(record.Failure)
	if err != nil {
		return ReviewRunReceipt{}, err
	}
	tasks := make([]ReviewTaskReceipt, len(record.Tasks))
	for index, taskRecord := range record.Tasks {
		kind, parseErr := parseTaskKind(taskRecord.Kind)
		if parseErr != nil {
			return ReviewRunReceipt{}, parseErr
		}
		taskStatus, statusErr := parseTaskRuntimeStatus(taskRecord.Status)
		if statusErr != nil {
			return ReviewRunReceipt{}, statusErr
		}
		taskFailure, failureErr := parseRunFailure(taskRecord.Failure)
		if failureErr != nil {
			return ReviewRunReceipt{}, failureErr
		}
		tasks[index] = ReviewTaskReceipt{
			key: taskRecord.Key, taskIdentity: taskRecord.TaskIdentity,
			inputIdentity: taskRecord.InputIdentity, handlerIdentity: taskRecord.HandlerIdentity,
			kind: kind, required: taskRecord.Required, status: taskStatus,
			attempts: taskRecord.Attempts, maxAttempts: taskRecord.MaxAttempts,
			leaseExpiresAtMillis: taskRecord.LeaseExpiresAtMilliseconds,
			outputIdentity:       taskRecord.OutputIdentity, failure: taskFailure,
			retryAtMillis: taskRecord.RetryAtMilliseconds,
		}
	}
	receipt := ReviewRunReceipt{
		identity: record.Identity, planIdentity: record.PlanIdentity, scope: scope, status: status,
		revision: record.Revision, headIdentity: record.HeadIdentity,
		lastOccurredAtMillis: record.LastOccurredAtMilliseconds,
		outputIdentity:       record.OutputIdentity, failure: failure, tasks: tasks,
	}
	if err := receipt.Validate(); err != nil {
		return ReviewRunReceipt{}, err
	}
	reencoded, err := EncodeReviewRunReceipt(receipt)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return ReviewRunReceipt{}, ErrInvalidReviewRunReceiptEncoding
	}
	return receipt, nil
}
func reviewRunReceiptToRecord(receipt ReviewRunReceipt) reviewRunReceiptRecord {
	tasks := make([]reviewTaskReceiptRecord, len(receipt.tasks))
	for index, task := range receipt.tasks {
		tasks[index] = reviewTaskReceiptRecord{
			Key: task.key, TaskIdentity: task.taskIdentity, InputIdentity: task.inputIdentity,
			HandlerIdentity: task.handlerIdentity, Kind: task.kind.String(), Required: task.required,
			Status: task.status.String(), Attempts: task.attempts, MaxAttempts: task.maxAttempts,
			LeaseExpiresAtMilliseconds: task.leaseExpiresAtMillis,
			OutputIdentity:             task.outputIdentity, Failure: task.failure.String(),
			RetryAtMilliseconds: task.retryAtMillis,
		}
	}
	return reviewRunReceiptRecord{
		Contract: "open-trestle/review-run-receipt", SchemaVersion: 1,
		Identity: receipt.identity, PlanIdentity: receipt.planIdentity,
		TenantID: receipt.scope.TenantID(), RepositoryID: receipt.scope.RepositoryID(),
		ReviewRunID: receipt.scope.ReviewRunID(), Status: receipt.status.String(),
		Revision: receipt.revision, HeadIdentity: receipt.headIdentity,
		LastOccurredAtMilliseconds: receipt.lastOccurredAtMillis,
		OutputIdentity:             receipt.outputIdentity, Failure: receipt.failure.String(), Tasks: tasks,
	}
}
func deriveReviewRunReceiptIdentity(receipt ReviewRunReceipt) string {
	record := reviewRunReceiptToRecord(receipt)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return hashControlPlaneValue(json.RawMessage(encoded))
}
func parseReviewRunStatus(value string) (ReviewRunStatus, error) {
	for status := ReviewRunActive; status <= ReviewRunCanceled; status++ {
		if status.String() == value {
			return status, nil
		}
	}
	return 0, ErrInvalidReviewRunReceipt
}
func parseTaskRuntimeStatus(value string) (TaskRuntimeStatus, error) {
	for status := TaskRuntimePending; status <= TaskRuntimeSkipped; status++ {
		if status.String() == value {
			return status, nil
		}
	}
	return 0, ErrInvalidReviewRunReceipt
}
