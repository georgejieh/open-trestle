package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/audit"
)

const maxEncodedRunEventBytes = 16 << 10

// ErrInvalidRunEventEncoding identifies noncanonical, unknown, or excessive event JSON.
var ErrInvalidRunEventEncoding = errors.New("invalid run event encoding")

type runEventRecord struct {
	Contract                   string `json:"contract"`
	SchemaVersion              int    `json:"schema_version"`
	Identity                   string `json:"identity"`
	PlanIdentity               string `json:"plan_identity"`
	TenantID                   string `json:"tenant_id"`
	RepositoryID               string `json:"repository_id"`
	ReviewRunID                string `json:"review_run_id"`
	Sequence                   uint64 `json:"sequence"`
	PreviousIdentity           string `json:"previous_identity"`
	Kind                       string `json:"kind"`
	TaskKey                    string `json:"task_key"`
	TaskIdentity               string `json:"task_identity"`
	Attempt                    uint8  `json:"attempt"`
	LeaseTokenIdentity         string `json:"lease_token_identity"`
	WorkerIdentity             string `json:"worker_identity"`
	LeaseExpiresAtMilliseconds int64  `json:"lease_expires_at_milliseconds"`
	OutputIdentity             string `json:"output_identity"`
	Failure                    string `json:"failure"`
	RetryAtMilliseconds        int64  `json:"retry_at_milliseconds"`
	OccurredAtMilliseconds     int64  `json:"occurred_at_milliseconds"`
}

// EncodeRunEvent emits bounded canonical JSON without lease secrets or raw errors.
func EncodeRunEvent(event RunEvent) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	record := runEventToRecord(event)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxEncodedRunEventBytes {
		return nil, ErrInvalidRunEventEncoding
	}
	return encoded, nil
}

// ParseRunEvent accepts only the exact canonical JSON representation.
func ParseRunEvent(encoded []byte) (RunEvent, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedRunEventBytes {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record runEventRecord
	if err := decoder.Decode(&record); err != nil {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	if record.Contract != "open-trestle/review-run-event-record" || record.SchemaVersion != 1 {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	kind, err := parseRunEventKind(record.Kind)
	if err != nil {
		return RunEvent{}, err
	}
	failure, err := parseRunFailure(record.Failure)
	if err != nil {
		return RunEvent{}, err
	}
	event := RunEvent{
		identity: record.Identity, planIdentity: record.PlanIdentity, scope: scope,
		sequence: record.Sequence, previousIdentity: record.PreviousIdentity, kind: kind,
		taskKey: record.TaskKey, taskIdentity: record.TaskIdentity, attempt: record.Attempt,
		leaseTokenIdentity: record.LeaseTokenIdentity, workerIdentity: record.WorkerIdentity,
		leaseExpiresAtMillis: record.LeaseExpiresAtMilliseconds, outputIdentity: record.OutputIdentity,
		failure: failure, retryAtMillis: record.RetryAtMilliseconds,
		occurredAtMillis: record.OccurredAtMilliseconds,
	}
	if err := event.Validate(); err != nil {
		return RunEvent{}, err
	}
	return event, nil
}
func runEventToRecord(event RunEvent) runEventRecord {
	return runEventRecord{
		Contract: "open-trestle/review-run-event-record", SchemaVersion: 1,
		Identity: event.Identity(), PlanIdentity: event.PlanIdentity(),
		TenantID: event.Scope().TenantID(), RepositoryID: event.Scope().RepositoryID(),
		ReviewRunID: event.Scope().ReviewRunID(), Sequence: event.Sequence(),
		PreviousIdentity: event.PreviousIdentity(), Kind: event.Kind().String(),
		TaskKey: event.TaskKey(), TaskIdentity: event.TaskIdentity(), Attempt: event.Attempt(),
		LeaseTokenIdentity: event.LeaseTokenIdentity(), WorkerIdentity: event.WorkerIdentity(),
		LeaseExpiresAtMilliseconds: event.leaseExpiresAtMillis, OutputIdentity: event.OutputIdentity(),
		Failure: event.Failure().String(), RetryAtMilliseconds: event.retryAtMillis,
		OccurredAtMilliseconds: event.occurredAtMillis,
	}
}
func parseRunEventKind(value string) (RunEventKind, error) {
	for kind := RunEventOpened; kind <= RunEventCanceled; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, ErrInvalidRunEventKind
}
func parseRunFailure(value string) (RunFailure, error) {
	if value == "" {
		return 0, nil
	}
	for failure := RunFailureTransient; failure <= RunFailureInternal; failure++ {
		if failure.String() == value {
			return failure, nil
		}
	}
	return 0, ErrInvalidRunEventFailure
}
