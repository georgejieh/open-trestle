package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxEncodedRunEventBytes   = 16 << 10
	maxEncodedRunEventV3Bytes = 16 << 20
	maxPreparedArtifactBytes  = 12 << 20
)

// ErrInvalidRunEventEncoding identifies noncanonical, unknown, or excessive event JSON.
var ErrInvalidRunEventEncoding = errors.New("invalid run event encoding")

type runEventRecord struct {
	Contract                   string                      `json:"contract"`
	SchemaVersion              int                         `json:"schema_version"`
	Identity                   string                      `json:"identity"`
	PlanIdentity               string                      `json:"plan_identity"`
	TenantID                   string                      `json:"tenant_id"`
	RepositoryID               string                      `json:"repository_id"`
	ReviewRunID                string                      `json:"review_run_id"`
	Sequence                   uint64                      `json:"sequence"`
	PreviousIdentity           string                      `json:"previous_identity"`
	Kind                       string                      `json:"kind"`
	TaskKey                    string                      `json:"task_key"`
	TaskIdentity               string                      `json:"task_identity"`
	Attempt                    uint8                       `json:"attempt"`
	LeaseTokenIdentity         string                      `json:"lease_token_identity"`
	WorkerIdentity             string                      `json:"worker_identity"`
	LeaseExpiresAtMilliseconds int64                       `json:"lease_expires_at_milliseconds"`
	OutputIdentity             string                      `json:"output_identity"`
	OutputKind                 string                      `json:"output_kind,omitempty"`
	Failure                    string                      `json:"failure"`
	FailureReason              string                      `json:"failure_reason,omitempty"`
	ContextShortfall           *taskFailureShortfallRecord `json:"context_shortfall,omitempty"`
	RetryAtMilliseconds        int64                       `json:"retry_at_milliseconds"`
	OccurredAtMilliseconds     int64                       `json:"occurred_at_milliseconds"`
	PreparedArtifact           []byte                      `json:"prepared_artifact,omitempty"`
	PacketDescriptor           *ContextPacketDescriptor    `json:"packet_descriptor,omitempty"`
	InputDescriptor            *ContextInputDescriptor     `json:"input_descriptor,omitempty"`
	RetryAfterMilliseconds     uint32                      `json:"retry_after_milliseconds,omitempty"`
}

// EncodeRunEvent emits bounded canonical JSON without lease secrets or raw errors.
func EncodeRunEvent(event RunEvent) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	record := runEventToRecord(event)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > runEventMaxBytes(event) {
		return nil, ErrInvalidRunEventEncoding
	}
	return encoded, nil
}

// ParseRunEvent accepts only the exact canonical JSON representation.
func ParseRunEvent(encoded []byte) (RunEvent, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedRunEventV3Bytes {
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
	if record.Contract != "open-trestle/review-run-event-record" || (record.SchemaVersion != 1 && record.SchemaVersion != 2 && record.SchemaVersion != 3 && record.SchemaVersion != 4 && record.SchemaVersion != 5 && record.SchemaVersion != 6 && record.SchemaVersion != 7) || len(encoded) > runEventMaxBytesForVersion(record.SchemaVersion) {
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
	reason, err := ParseTaskFailureReason(record.FailureReason)
	if err != nil {
		return RunEvent{}, err
	}
	// An all-zero shortfall object is absent counts in a non-canonical form;
	// it would re-encode without the object under the same identity.
	if record.ContextShortfall != nil && !taskFailureShortfallFromRecord(record.ContextShortfall).Present() {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	event := RunEvent{
		identity: record.Identity, planIdentity: record.PlanIdentity, scope: scope,
		sequence: record.Sequence, previousIdentity: record.PreviousIdentity, kind: kind,
		taskKey: record.TaskKey, taskIdentity: record.TaskIdentity, attempt: record.Attempt,
		leaseTokenIdentity: record.LeaseTokenIdentity, workerIdentity: record.WorkerIdentity,
		leaseExpiresAtMillis: record.LeaseExpiresAtMilliseconds, outputIdentity: record.OutputIdentity,
		failure: failure, failureReason: reason, shortfall: taskFailureShortfallFromRecord(record.ContextShortfall), retryAtMillis: record.RetryAtMilliseconds,
		occurredAtMillis: record.OccurredAtMilliseconds, preparedArtifact: append([]byte(nil), record.PreparedArtifact...),
		retryAfterMillis: record.RetryAfterMilliseconds,
	}
	if record.PacketDescriptor != nil {
		if record.SchemaVersion != 4 {
			return RunEvent{}, ErrInvalidRunEventEncoding
		}
		event.packetDescriptor = clonePacketDescriptor(*record.PacketDescriptor)
	}
	if record.InputDescriptor != nil {
		if record.SchemaVersion != 5 {
			return RunEvent{}, ErrInvalidRunEventEncoding
		}
		event.inputDescriptor = cloneContextInputDescriptor(*record.InputDescriptor)
	}
	if err := event.Validate(); err != nil || record.SchemaVersion != runEventVersion(event) || record.OutputKind != eventContextFailureOutputKind(event) {
		return RunEvent{}, ErrInvalidRunEventEncoding
	}
	return event, nil
}
func runEventToRecord(event RunEvent) runEventRecord {
	record := runEventRecord{
		Contract: "open-trestle/review-run-event-record", SchemaVersion: runEventVersion(event),
		Identity: event.Identity(), PlanIdentity: event.PlanIdentity(),
		TenantID: event.Scope().TenantID(), RepositoryID: event.Scope().RepositoryID(),
		ReviewRunID: event.Scope().ReviewRunID(), Sequence: event.Sequence(),
		PreviousIdentity: event.PreviousIdentity(), Kind: event.Kind().String(),
		TaskKey: event.TaskKey(), TaskIdentity: event.TaskIdentity(), Attempt: event.Attempt(),
		LeaseTokenIdentity: event.LeaseTokenIdentity(), WorkerIdentity: event.WorkerIdentity(),
		LeaseExpiresAtMilliseconds: event.leaseExpiresAtMillis, OutputIdentity: event.OutputIdentity(), OutputKind: eventContextFailureOutputKind(event),
		Failure: event.Failure().String(), FailureReason: event.failureReason.String(), ContextShortfall: taskFailureShortfallToRecord(event.shortfall), RetryAtMilliseconds: event.retryAtMillis,
		OccurredAtMilliseconds: event.occurredAtMillis, PreparedArtifact: event.PreparedArtifact(),
		RetryAfterMilliseconds: event.retryAfterMillis,
	}
	if event.kind == RunEventContextInputPrepared {
		d := event.InputDescriptor()
		record.InputDescriptor = &d
	}
	if event.kind == RunEventContextPacketPrepared {
		d := event.PacketDescriptor()
		record.PacketDescriptor = &d
	}
	return record
}
func parseRunEventKind(value string) (RunEventKind, error) {
	for kind := RunEventOpened; kind <= RunEventContextInputSettled; kind++ {
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

func eventContextFailureOutputKind(event RunEvent) string {
	return contextFailureOutputKind(event.kind == RunEventContextAbstentionPrepared || event.kind == RunEventTaskFailed && event.outputIdentity != "")
}
func runEventVersion(event RunEvent) int {
	if event.failureReason != 0 {
		return 7
	}
	if event.kind == RunEventContextInputSettled {
		return 6
	}
	if event.kind == RunEventContextInputPrepared {
		return 5
	}
	if event.kind == RunEventContextPacketPrepared {
		return 4
	}
	if event.kind == RunEventContextAbstentionPrepared {
		return 3
	}
	if event.kind == RunEventTaskFailed && event.outputIdentity != "" {
		return 2
	}
	return 1
}

func runEventMaxBytes(event RunEvent) int { return runEventMaxBytesForVersion(runEventVersion(event)) }
func runEventMaxBytesForVersion(version int) int {
	if version == 3 {
		return maxEncodedRunEventV3Bytes
	}
	return maxEncodedRunEventBytes
}
