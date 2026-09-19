package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/controlplane"
	"io"
	"time"
)

const maxWorkerRequestBytes = 16 << 10

var ErrInvalidWorkerRequest = errors.New("invalid review worker request")

type taskClaimRequestRecord struct {
	Contract        string `json:"contract"`
	SchemaVersion   int    `json:"schema_version"`
	HandlerIdentity string `json:"handler_identity"`
}

func parseTaskClaimRequest(encoded []byte) (string, error) {
	var record taskClaimRequestRecord
	if err := decodeCanonicalWorkerRequest(encoded, &record); err != nil {
		return "", ErrInvalidWorkerRequest
	}
	validContract := record.Contract == "open-trestle/task-claim-request" && record.SchemaVersion == 1
	if !validContract || controlplane.ValidateHandlerIdentity(record.HandlerIdentity) != nil {
		return "", ErrInvalidWorkerRequest
	}
	return record.HandlerIdentity, nil
}

type taskCompletionRequestRecord struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	Lease         json.RawMessage `json:"lease"`
	Completion    json.RawMessage `json:"completion"`
}

func parseTaskCompletionRequest(encoded []byte) (controlplane.TaskLease, controlplane.TaskCompletion, error) {
	var record taskCompletionRequestRecord
	if err := decodeCanonicalWorkerRequest(encoded, &record); err != nil || record.Contract != "open-trestle/task-completion-request" || record.SchemaVersion != 1 {
		return controlplane.TaskLease{}, controlplane.TaskCompletion{}, ErrInvalidWorkerRequest
	}
	lease, err := controlplane.ParseTaskLease(record.Lease)
	if err != nil {
		return controlplane.TaskLease{}, controlplane.TaskCompletion{}, ErrInvalidWorkerRequest
	}
	completion, err := controlplane.ParseTaskCompletion(record.Completion)
	if err != nil {
		return controlplane.TaskLease{}, controlplane.TaskCompletion{}, ErrInvalidWorkerRequest
	}
	return lease, completion, nil
}
func decodeCanonicalWorkerRequest(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maxWorkerRequestBytes {
		return ErrInvalidWorkerRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidWorkerRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidWorkerRequest
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidWorkerRequest
	}
	return nil
}

type taskNotificationClaimRequestRecord struct {
	Contract                  string `json:"contract"`
	SchemaVersion             int    `json:"schema_version"`
	WaitMilliseconds          uint32 `json:"wait_milliseconds"`
	LeaseDurationMilliseconds uint32 `json:"lease_duration_milliseconds"`
}

func parseTaskNotificationClaimRequest(encoded []byte) (time.Duration, time.Duration, error) {
	var record taskNotificationClaimRequestRecord
	if decodeCanonicalWorkerRequest(encoded, &record) != nil || record.Contract != "open-trestle/task-notification-claim-request" || record.SchemaVersion != 1 || record.WaitMilliseconds > 10_000 || record.LeaseDurationMilliseconds < 1_000 || record.LeaseDurationMilliseconds > 86_400_000 {
		return 0, 0, ErrInvalidWorkerRequest
	}
	return time.Duration(record.WaitMilliseconds) * time.Millisecond, time.Duration(record.LeaseDurationMilliseconds) * time.Millisecond, nil
}
