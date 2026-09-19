package controlplane

import (
	"bytes"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"io"
)

const maxEncodedTaskNotificationBytes = 16 << 10

type taskNotificationRecord struct {
	Contract                string `json:"contract"`
	SchemaVersion           int    `json:"schema_version"`
	Identity                string `json:"identity"`
	TenantID                string `json:"tenant_id"`
	RepositoryID            string `json:"repository_id"`
	ReviewRunID             string `json:"review_run_id"`
	PlanIdentity            string `json:"plan_identity"`
	TaskStateRevision       uint64 `json:"task_state_revision"`
	TaskStateEventIdentity  string `json:"task_state_event_identity"`
	TaskKey                 string `json:"task_key"`
	TaskIdentity            string `json:"task_identity"`
	HandlerIdentity         string `json:"handler_identity"`
	Attempt                 uint8  `json:"attempt"`
	AvailableAtMilliseconds int64  `json:"available_at_milliseconds"`
}

func EncodeTaskNotification(n TaskNotification) ([]byte, error) {
	if n.Validate() != nil {
		return nil, ErrInvalidTaskNotificationEncoding
	}
	encoded, err := json.Marshal(taskNotificationToRecord(n))
	if err != nil || len(encoded) > maxEncodedTaskNotificationBytes {
		return nil, ErrInvalidTaskNotificationEncoding
	}
	return encoded, nil
}
func ParseTaskNotification(encoded []byte) (TaskNotification, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedTaskNotificationBytes {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record taskNotificationRecord
	if decoder.Decode(&record) != nil {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/task-notification" || record.SchemaVersion != 1 {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	return taskNotificationFromRecord(record)
}
func taskNotificationToRecord(n TaskNotification) taskNotificationRecord {
	return taskNotificationRecord{"open-trestle/task-notification", 1, n.identity, n.scope.TenantID(), n.scope.RepositoryID(), n.scope.ReviewRunID(), n.planIdentity, n.taskStateRevision, n.taskStateEventIdentity, n.taskKey, n.taskIdentity, n.handlerIdentity, n.attempt, n.availableAtMillis}
}

type taskNotificationLeaseRecord struct {
	Contract              string                 `json:"contract"`
	SchemaVersion         int                    `json:"schema_version"`
	Identity              string                 `json:"identity"`
	Notification          taskNotificationRecord `json:"notification"`
	WorkerIdentity        string                 `json:"worker_identity"`
	Token                 string                 `json:"token"`
	TokenIdentity         string                 `json:"token_identity"`
	Delivery              uint8                  `json:"delivery"`
	LeasedAtMilliseconds  int64                  `json:"leased_at_milliseconds"`
	ExpiresAtMilliseconds int64                  `json:"expires_at_milliseconds"`
}

// EncodeTaskNotificationLease emits a bounded secret-bearing transport record.
func EncodeTaskNotificationLease(lease TaskNotificationLease) ([]byte, error) {
	if lease.Validate() != nil {
		return nil, ErrInvalidTaskNotificationEncoding
	}
	record := taskNotificationLeaseRecord{"open-trestle/task-notification-lease", 1, lease.identity, taskNotificationToRecord(lease.notification), lease.workerIdentity, lease.token, lease.tokenIdentity, lease.delivery, lease.leasedAtMillis, lease.expiresAtMillis}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxEncodedTaskNotificationBytes*2 {
		return nil, ErrInvalidTaskNotificationEncoding
	}
	return encoded, nil
}

// ParseTaskNotificationLease accepts only an exact canonical secret-bearing record.
func ParseTaskNotificationLease(encoded []byte) (TaskNotificationLease, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedTaskNotificationBytes*2 {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record taskNotificationLeaseRecord
	if decoder.Decode(&record) != nil {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/task-notification-lease" || record.SchemaVersion != 1 {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	notification, err := taskNotificationFromRecord(record.Notification)
	if err != nil {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	lease, err := NewTaskNotificationLease(notification, record.WorkerIdentity, record.Token, record.Delivery, runMillisToTime(record.LeasedAtMilliseconds), runMillisToTime(record.ExpiresAtMilliseconds))
	if err != nil || lease.identity != record.Identity || lease.tokenIdentity != record.TokenIdentity {
		return TaskNotificationLease{}, ErrInvalidTaskNotificationEncoding
	}
	return lease, nil
}
func taskNotificationFromRecord(record taskNotificationRecord) (TaskNotification, error) {
	if record.Contract != "open-trestle/task-notification" || record.SchemaVersion != 1 {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	n := TaskNotification{identity: record.Identity, scope: scope, planIdentity: record.PlanIdentity, taskStateRevision: record.TaskStateRevision, taskStateEventIdentity: record.TaskStateEventIdentity, taskKey: record.TaskKey, taskIdentity: record.TaskIdentity, handlerIdentity: record.HandlerIdentity, attempt: record.Attempt, availableAtMillis: record.AvailableAtMilliseconds}
	if n.Validate() != nil {
		return TaskNotification{}, ErrInvalidTaskNotificationEncoding
	}
	return n, nil
}
