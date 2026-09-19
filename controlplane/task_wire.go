package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	maxEncodedTaskLeaseBytes      = 8 << 10
	maxEncodedTaskCompletionBytes = 2 << 10
)

var (
	// ErrInvalidTaskLeaseEncoding identifies noncanonical, unknown, or excessive capability JSON.
	ErrInvalidTaskLeaseEncoding = errors.New("invalid review task lease encoding")
	// ErrInvalidTaskCompletionEncoding identifies noncanonical, unknown, or excessive completion JSON.
	ErrInvalidTaskCompletionEncoding = errors.New("invalid review task completion encoding")
)

type taskLeaseRecord struct {
	Contract              string `json:"contract"`
	SchemaVersion         int    `json:"schema_version"`
	Identity              string `json:"identity"`
	PlanIdentity          string `json:"plan_identity"`
	TaskKey               string `json:"task_key"`
	TaskIdentity          string `json:"task_identity"`
	HandlerIdentity       string `json:"handler_identity"`
	WorkerIdentity        string `json:"worker_identity"`
	Attempt               uint8  `json:"attempt"`
	Token                 string `json:"token"`
	TokenIdentity         string `json:"token_identity"`
	EventIdentity         string `json:"event_identity"`
	ExpiresAtMilliseconds int64  `json:"expires_at_milliseconds"`
}

func EncodeTaskLease(lease TaskLease) ([]byte, error) {
	if err := lease.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(taskLeaseToRecord(lease))
	if err != nil || len(encoded) > maxEncodedTaskLeaseBytes {
		return nil, ErrInvalidTaskLeaseEncoding
	}
	return encoded, nil
}
func ParseTaskLease(encoded []byte) (TaskLease, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedTaskLeaseBytes {
		return TaskLease{}, ErrInvalidTaskLeaseEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record taskLeaseRecord
	if err := decoder.Decode(&record); err != nil {
		return TaskLease{}, ErrInvalidTaskLeaseEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return TaskLease{}, ErrInvalidTaskLeaseEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/review-task-lease" || record.SchemaVersion != 1 {
		return TaskLease{}, ErrInvalidTaskLeaseEncoding
	}
	lease := TaskLease{
		identity: record.Identity, planIdentity: record.PlanIdentity,
		taskKey: record.TaskKey, taskIdentity: record.TaskIdentity,
		handlerIdentity: record.HandlerIdentity, workerIdentity: record.WorkerIdentity,
		attempt: record.Attempt, token: record.Token, tokenIdentity: record.TokenIdentity,
		eventIdentity: record.EventIdentity, expiresAtMillis: record.ExpiresAtMilliseconds,
	}
	if err := lease.Validate(); err != nil {
		return TaskLease{}, err
	}
	return lease, nil
}
func taskLeaseToRecord(lease TaskLease) taskLeaseRecord {
	return taskLeaseRecord{
		Contract: "open-trestle/review-task-lease", SchemaVersion: 1,
		Identity: lease.identity, PlanIdentity: lease.planIdentity,
		TaskKey: lease.taskKey, TaskIdentity: lease.taskIdentity,
		HandlerIdentity: lease.handlerIdentity, WorkerIdentity: lease.workerIdentity,
		Attempt: lease.attempt, Token: lease.token, TokenIdentity: lease.tokenIdentity,
		EventIdentity: lease.eventIdentity, ExpiresAtMilliseconds: lease.expiresAtMillis,
	}
}

type taskCompletionRecord struct {
	Contract       string `json:"contract"`
	SchemaVersion  int    `json:"schema_version"`
	Identity       string `json:"identity"`
	Status         string `json:"status"`
	OutputIdentity string `json:"output_identity"`
	Failure        string `json:"failure"`
}

func EncodeTaskCompletion(completion TaskCompletion) ([]byte, error) {
	if err := completion.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(taskCompletionToRecord(completion))
	if err != nil || len(encoded) > maxEncodedTaskCompletionBytes {
		return nil, ErrInvalidTaskCompletionEncoding
	}
	return encoded, nil
}
func ParseTaskCompletion(encoded []byte) (TaskCompletion, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedTaskCompletionBytes {
		return TaskCompletion{}, ErrInvalidTaskCompletionEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record taskCompletionRecord
	if err := decoder.Decode(&record); err != nil {
		return TaskCompletion{}, ErrInvalidTaskCompletionEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return TaskCompletion{}, ErrInvalidTaskCompletionEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/review-task-completion" || record.SchemaVersion != 1 {
		return TaskCompletion{}, ErrInvalidTaskCompletionEncoding
	}
	status, err := parseTaskCompletionStatus(record.Status)
	if err != nil {
		return TaskCompletion{}, err
	}
	failure, err := parseRunFailure(record.Failure)
	if err != nil {
		return TaskCompletion{}, err
	}
	completion := TaskCompletion{identity: record.Identity, status: status, outputIdentity: record.OutputIdentity, failure: failure}
	if err := completion.Validate(); err != nil {
		return TaskCompletion{}, err
	}
	return completion, nil
}
func taskCompletionToRecord(completion TaskCompletion) taskCompletionRecord {
	return taskCompletionRecord{
		Contract: "open-trestle/review-task-completion", SchemaVersion: 1,
		Identity: completion.identity, Status: completion.status.String(),
		OutputIdentity: completion.outputIdentity, Failure: completion.failure.String(),
	}
}
func parseTaskCompletionStatus(value string) (TaskCompletionStatus, error) {
	for status := TaskCompletionSucceeded; status <= TaskCompletionFailed; status++ {
		if status.String() == value {
			return status, nil
		}
	}
	return 0, ErrInvalidTaskCompletionEncoding
}
