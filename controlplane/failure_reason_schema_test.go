package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// schemaRecords returns every encoded completion, event and receipt of one run
// whose context or source task records reason, each with its schema $id.
func schemaRecords(t *testing.T, reason TaskFailureReason, shortfall TaskFailureContextShortfall) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := inventoryPlan(t, "tenant", "repository", "run-schema-"+reason.String())
	coordinator := inventoryOpen(t, journal, plan)
	var completion TaskCompletion
	if reason == TaskFailureReasonRouteContextInsufficient || reason == TaskFailureReasonNoEligibleRoute {
		lease := inventoryPreparedLease(t, coordinator, plan)
		task, _ := plan.Task("context")
		if completion, err = NewContextTaskRefusal(reason, shortfall, plan, task); err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(500)); err != nil {
			t.Fatal(err)
		}
	} else {
		task, _ := plan.Task("source")
		lease, ok, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(200))
		if err != nil || !ok {
			t.Fatalf("claim source: %v", err)
		}
		if completion, err = NewSourceTaskFailureWithReason(RunFailurePolicy, reason, plan, task); err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(201)); err != nil {
			t.Fatal(err)
		}
	}
	records := map[string][]byte{}
	encoded, err := EncodeTaskCompletion(completion)
	if err != nil {
		t.Fatal(err)
	}
	records["completion"] = encoded
	events, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		encoded, err := EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		records[fmt.Sprintf("event-%02d", i)] = encoded
	}
	_, state, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if records["receipt"], err = EncodeReviewRunReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	return records
}

func recordSchemaID(t *testing.T, name string, encoded []byte) string {
	t.Helper()
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &header); err != nil || header.SchemaVersion == 0 {
		t.Fatalf("%s has no schema version: %v", name, err)
	}
	kind := map[string]string{"completion": "review-task-completion", "receipt": "review-run-receipt"}[name]
	if kind == "" {
		kind = "review-run-event"
	}
	return fmt.Sprintf("urn:open-trestle:schema:controlplane:%s:v%d", kind, header.SchemaVersion)
}

// Every encoded completion, run event and receipt of a run with a recorded
// failure reason validates in full against its versioned schema, and the
// schemas refuse a reason or count set the runtime would refuse.
func TestFailureReasonRecordsValidateAgainstSchemas(t *testing.T) {
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	shortfall := TaskFailureContextShortfall{RequiredTokens: 14096, EstimatedInputTokens: 10000, MaxOutputTokens: 4096, DeclaredContextTokens: 8192}
	counts := []byte(`,"context_shortfall":{"required_tokens":14096,"estimated_input_tokens":10000,"max_output_tokens":4096,"declared_context_tokens":8192}`)
	for _, reason := range []TaskFailureReason{TaskFailureReasonRouteContextInsufficient, TaskFailureReasonNoEligibleRoute, TaskFailureReasonNoMergeBase, TaskFailureReasonNothingToReview, TaskFailureReasonMergeBaseUnavailable} {
		t.Run(reason.String(), func(t *testing.T) {
			s := TaskFailureContextShortfall{}
			if reason == TaskFailureReasonRouteContextInsufficient {
				s = shortfall
			}
			reasoned := 0
			for name, encoded := range schemaRecords(t, reason, s) {
				id := recordSchemaID(t, name, encoded)
				if err := registry.Validate(id, encoded); err != nil {
					t.Fatalf("%s (%s): %v\n%s", name, id, err, encoded)
				}
				marker := []byte(`"failure_reason":"` + reason.String() + `"`)
				if !bytes.Contains(encoded, marker) {
					continue
				}
				reasoned++
				var forgeries [][]byte
				if reason == TaskFailureReasonRouteContextInsufficient {
					forgeries = append(forgeries, bytes.Replace(encoded, counts, nil, 1))
					forgeries = append(forgeries, bytes.Replace(encoded, marker, []byte(`"failure_reason":"no_eligible_route"`), 1))
					forgeries = append(forgeries, bytes.Replace(encoded, []byte(`"required_tokens":14096`), []byte(`"required_tokens":1`), 1))
				} else {
					forgeries = append(forgeries, bytes.Replace(encoded, marker, append(append([]byte{}, marker...), counts...), 1))
				}
				forgeries = append(forgeries, bytes.Replace(encoded, marker, []byte(`"failure_reason":"unknown_reason"`), 1))
				for i, forged := range forgeries {
					if bytes.Equal(forged, encoded) {
						t.Fatalf("%s forgery %d did not apply", name, i)
					}
					if err := registry.Validate(id, forged); err == nil {
						t.Fatalf("%s forgery %d validated against %s:\n%s", name, i, id, forged)
					}
				}
			}
			if reasoned != 3 {
				t.Fatalf("%d records carry the reason, want completion, event and receipt", reasoned)
			}
		})
	}
}
