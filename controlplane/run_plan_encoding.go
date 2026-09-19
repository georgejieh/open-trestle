package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/audit"
)

const maxEncodedReviewRunPlanBytes = 128 << 10

// ErrInvalidReviewRunPlanEncoding identifies noncanonical, unknown, or excessive plan JSON.
var ErrInvalidReviewRunPlanEncoding = errors.New("invalid review run plan encoding")

type taskDefinitionRecord struct {
	Identity                  string   `json:"identity"`
	Key                       string   `json:"key"`
	Kind                      string   `json:"kind"`
	InputIdentity             string   `json:"input_identity"`
	HandlerIdentity           string   `json:"handler_identity"`
	Dependencies              []string `json:"dependencies"`
	MaxAttempts               uint8    `json:"max_attempts"`
	RetryDelayMilliseconds    uint32   `json:"retry_delay_milliseconds"`
	LeaseDurationMilliseconds uint32   `json:"lease_duration_milliseconds"`
	Required                  bool     `json:"required"`
}
type reviewRunPlanRecord struct {
	Contract        string                 `json:"contract"`
	SchemaVersion   int                    `json:"schema_version"`
	Identity        string                 `json:"identity"`
	TenantID        string                 `json:"tenant_id"`
	RepositoryID    string                 `json:"repository_id"`
	ReviewRunID     string                 `json:"review_run_id"`
	RequestIdentity string                 `json:"request_identity"`
	PolicyIdentity  string                 `json:"policy_identity"`
	Mode            string                 `json:"mode"`
	Tasks           []taskDefinitionRecord `json:"tasks"`
}

// EncodeReviewRunPlan emits bounded canonical JSON for durable restart.
func EncodeReviewRunPlan(plan ReviewRunPlan) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	record := reviewRunPlanToRecord(plan)
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxEncodedReviewRunPlanBytes {
		return nil, ErrInvalidReviewRunPlanEncoding
	}
	return encoded, nil
}

// ParseReviewRunPlan accepts only the exact canonical representation.
func ParseReviewRunPlan(encoded []byte) (ReviewRunPlan, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedReviewRunPlanBytes {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record reviewRunPlanRecord
	if err := decoder.Decode(&record); err != nil {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	if record.Contract != "open-trestle/review-run-plan-record" || record.SchemaVersion != 1 {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	mode, err := parseReviewRunMode(record.Mode)
	if err != nil {
		return ReviewRunPlan{}, err
	}
	tasks := make([]TaskDefinition, len(record.Tasks))
	for index, taskRecord := range record.Tasks {
		kind, parseErr := parseTaskKind(taskRecord.Kind)
		if parseErr != nil {
			return ReviewRunPlan{}, parseErr
		}
		task, taskErr := NewTaskDefinition(
			taskRecord.Key, kind, taskRecord.InputIdentity, taskRecord.HandlerIdentity,
			taskRecord.Dependencies, taskRecord.MaxAttempts, taskRecord.RetryDelayMilliseconds,
			taskRecord.LeaseDurationMilliseconds, taskRecord.Required,
		)
		if taskErr != nil || task.Identity() != taskRecord.Identity {
			return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
		}
		tasks[index] = task
	}
	plan, err := NewReviewRunPlan(scope, record.RequestIdentity, record.PolicyIdentity, mode, tasks)
	if err != nil {
		return ReviewRunPlan{}, err
	}
	if plan.Identity() != record.Identity {
		return ReviewRunPlan{}, ErrInvalidReviewRunIdentity
	}
	reencoded, err := EncodeReviewRunPlan(plan)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	return plan, nil
}
func reviewRunPlanToRecord(plan ReviewRunPlan) reviewRunPlanRecord {
	tasks := plan.Tasks()
	taskRecords := make([]taskDefinitionRecord, len(tasks))
	for index, task := range tasks {
		taskRecords[index] = taskDefinitionRecord{
			Identity: task.Identity(), Key: task.Key(), Kind: task.Kind().String(),
			InputIdentity: task.InputIdentity(), HandlerIdentity: task.HandlerIdentity(),
			Dependencies: task.Dependencies(), MaxAttempts: task.MaxAttempts(),
			RetryDelayMilliseconds:    task.RetryDelayMilliseconds(),
			LeaseDurationMilliseconds: task.LeaseDurationMilliseconds(), Required: task.Required(),
		}
	}
	return reviewRunPlanRecord{
		Contract: "open-trestle/review-run-plan-record", SchemaVersion: 1,
		Identity: plan.Identity(), TenantID: plan.Scope().TenantID(),
		RepositoryID: plan.Scope().RepositoryID(), ReviewRunID: plan.Scope().ReviewRunID(),
		RequestIdentity: plan.RequestIdentity(), PolicyIdentity: plan.PolicyIdentity(),
		Mode: plan.Mode().String(), Tasks: taskRecords,
	}
}
func parseReviewRunMode(value string) (ReviewRunMode, error) {
	for mode := ReviewRunLocal; mode <= ReviewRunRequired; mode++ {
		if mode.String() == value {
			return mode, nil
		}
	}
	return 0, ErrInvalidReviewRunMode
}
func parseTaskKind(value string) (TaskKind, error) {
	for kind := TaskAcquireSource; kind <= TaskPublishResult; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, ErrInvalidReviewTaskKind
}
