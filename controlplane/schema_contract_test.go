package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type schemaContractDocument struct {
	ID                   string   `json:"$id"`
	Type                 string   `json:"type"`
	AdditionalProperties bool     `json:"additionalProperties"`
	Required             []string `json:"required"`
	Properties           map[string]struct {
		Const any `json:"const"`
	} `json:"properties"`
}

func TestControlPlaneSchemasMatchCanonicalRecordShapes(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
	availableState, _ := coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	runtime, _ := availableState.Task("source")
	notification, err := NewTaskNotification(availableState, runtime, time.UnixMilli(110))
	if err != nil {
		t.Fatal(err)
	}
	notificationLease, err := NewTaskNotificationLease(notification, "worker-a", strings.Repeat("f", 64), 1, time.UnixMilli(200), time.UnixMilli(1200))
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-a", time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err = coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	cases := []struct {
		schema  string
		encoded []byte
	}{{"review-run-plan-v1.schema.json", mustEncodeRunPlan(t, plan)}, {"review-run-event-v1.schema.json", mustEncodeRunEvent(t, events[0])}, {"review-run-receipt-v1.schema.json", mustEncodeRunReceipt(t, receipt)}, {"review-task-lease-v1.schema.json", mustEncodeTaskLease(t, lease)}, {"review-task-completion-v1.schema.json", mustEncodeTaskCompletion(t, completion)}, {"task-notification-v1.schema.json", mustEncodeTaskNotification(t, notification)}, {"task-notification-lease-v1.schema.json", mustEncodeTaskNotificationLease(t, notificationLease)}}
	for _, test := range cases {
		t.Run(test.schema, func(t *testing.T) {
			assertSchemaRecordShape(t, filepath.Join("..", "schemas", "controlplane", test.schema), test.encoded)
		})
	}
}
func assertSchemaRecordShape(t *testing.T, path string, encoded []byte) {
	t.Helper()
	schemaBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema schemaContractDocument
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.ID == "" || schema.Type != "object" || schema.AdditionalProperties || len(schema.Required) == 0 {
		t.Fatalf("invalid schema metadata: %#v", schema)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	required := make(map[string]bool, len(schema.Required))
	for _, key := range schema.Required {
		required[key] = true
		if _, exists := record[key]; !exists {
			t.Fatalf("required property %q missing from record", key)
		}
	}
	for key := range record {
		if _, declared := schema.Properties[key]; !declared {
			t.Fatalf("record property %q absent from schema", key)
		}
	}
	for _, key := range []string{"contract", "schema_version"} {
		property := schema.Properties[key]
		if property.Const == nil {
			t.Fatalf("schema property %q has no const", key)
		}
		var actual any
		if err := json.Unmarshal(record[key], &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, property.Const) {
			t.Fatalf("%s=%v want %v", key, actual, property.Const)
		}
	}
}
func mustEncodeRunPlan(t *testing.T, plan ReviewRunPlan) []byte {
	t.Helper()
	encoded, err := EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeTaskNotification(t *testing.T, value TaskNotification) []byte {
	t.Helper()
	encoded, err := EncodeTaskNotification(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func mustEncodeTaskNotificationLease(t *testing.T, value TaskNotificationLease) []byte {
	t.Helper()
	encoded, err := EncodeTaskNotificationLease(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
