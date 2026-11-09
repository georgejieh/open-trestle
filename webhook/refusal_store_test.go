package webhook

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingInbox interface {
	Store
	RefusalStore
}

// Both local inboxes record one refusal per delivery and planner, keep the
// first record on repetition, refuse a different reason, and never list or
// replay-index refusal records as deliveries.
func TestInboxStoresRecordRefusalsOncePerDeliveryAndPlanner(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	fileStore, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]recordingInbox{"memory": NewMemoryStore(), "file": fileStore} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			scope, _ := NewRepositoryScope("tenant-a", "repo-a")
			delivery, err := NewVerifiedDelivery(scope, SourceGitHub, "delivery-"+name, "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"store":"`+name+`"}`), time.UnixMilli(1000))
			if err != nil {
				t.Fatal(err)
			}
			stored, _, err := store.Put(ctx, delivery, time.UnixMilli(1000))
			if err != nil {
				t.Fatal(err)
			}
			planner := strings.Repeat("d", 64)
			record, err := NewRefusalRecord(stored, planner, "invalid_payload", time.UnixMilli(2000))
			if err != nil {
				t.Fatal(err)
			}
			if _, created, err := store.RecordRefusal(ctx, record); err != nil || !created {
				t.Fatalf("record=(%t,%v)", created, err)
			}
			later, _ := NewRefusalRecord(stored, planner, "invalid_payload", time.UnixMilli(3000))
			if kept, created, err := store.RecordRefusal(ctx, later); err != nil || created || kept.Identity() != record.Identity() {
				t.Fatalf("repeat=(%t,%v)", created, err)
			}
			different, _ := NewRefusalRecord(stored, planner, RefusalReasonPlanningRefused, time.UnixMilli(3000))
			if _, _, err := store.RecordRefusal(ctx, different); !errors.Is(err, ErrRefusalConflict) {
				t.Fatalf("conflict err=%v", err)
			}
			otherPlanner, _ := NewRefusalRecord(stored, strings.Repeat("e", 64), RefusalReasonPlanningRefused, time.UnixMilli(3000))
			if _, created, err := store.RecordRefusal(ctx, otherPlanner); err != nil || !created {
				t.Fatalf("another planner's refusal=(%t,%v)", created, err)
			}
			loaded, found, err := store.Refusal(ctx, scope, SourceGitHub, delivery.DeduplicationKey(), planner)
			if err != nil || !found || loaded.Identity() != record.Identity() || loaded.Reason() != "invalid_payload" {
				t.Fatalf("refusal=(%t,%v)", found, err)
			}
			listed, err := store.List(ctx, scope, SourceGitHub, "", 100)
			if err != nil || len(listed) != 1 {
				t.Fatalf("refusals changed the delivery listing: %d %v", len(listed), err)
			}
			unknown, _ := NewVerifiedDelivery(scope, SourceGitHub, "never-stored-"+name, "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"stored":false}`), time.UnixMilli(1000))
			unstored, _ := NewStoredDelivery(unknown, time.UnixMilli(1000))
			orphan, _ := NewRefusalRecord(unstored, planner, "invalid_payload", time.UnixMilli(2000))
			if _, _, err := store.RecordRefusal(ctx, orphan); !errors.Is(err, ErrInvalidRefusalRecord) {
				t.Fatalf("refusal of an unstored delivery err=%v", err)
			}
		})
	}
	if err := fileStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := NewVerifiedDelivery(scope, SourceGitHub, "delivery-file", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"store":"file"}`), time.UnixMilli(1000))
	record, found, err := reopened.Refusal(context.Background(), scope, SourceGitHub, delivery.DeduplicationKey(), strings.Repeat("d", 64))
	if err != nil || !found || record.Reason() != "invalid_payload" {
		t.Fatalf("reopened refusal=(%t,%v)", found, err)
	}
	encoded, err := EncodeRefusalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseRefusalRecord(encoded); err != nil || parsed.Identity() != record.Identity() {
		t.Fatalf("refusal readback: %v", err)
	}
	for _, forged := range []string{strings.Replace(string(encoded), `"invalid_payload"`, `"Invalid Payload"`, 1), strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":2`, 1), strings.Replace(string(encoded), `"reason":"invalid_payload"`, `"reason":"planning_refused"`, 1)} {
		if _, err := ParseRefusalRecord([]byte(forged)); err == nil {
			t.Fatal("refusal record accepted a noncanonical reason, version, or identity")
		}
	}
}

func TestDeliveryRefusalCarriesItsReason(t *testing.T) {
	named := NewDeliveryRefusal("invalid_payload", "invalid payload")
	if reason, refused := DeliveryRefusalReason(named); !refused || reason != "invalid_payload" || !errors.Is(named, ErrDeliveryRefused) {
		t.Fatal("named refusal lost its reason")
	}
	wrapped := refuseDelivery(RefusalReasonRunPlanNotBound, ErrRunPlanNotBound)
	if reason, refused := DeliveryRefusalReason(wrapped); !refused || reason != RefusalReasonRunPlanNotBound || !errors.Is(wrapped, ErrRunPlanNotBound) {
		t.Fatal("processor refusal lost its reason or cause")
	}
	if _, refused := DeliveryRefusalReason(errors.New("transient")); refused {
		t.Fatal("an ordinary error was treated as a refusal")
	}
	if NewDeliveryRefusal("Not A Token", "x").Reason() != RefusalReasonPlanningRefused {
		t.Fatal("an invalid reason token was accepted")
	}
	// A conflict is any plan in the scope the planner did not produce for the
	// delivery, including one that names the delivery's own request.
	if explanation := RefusalExplanation(RefusalReasonRunPlanConflict); explanation != "the run scope holds a plan the planner did not produce for this delivery" {
		t.Fatalf("run_plan_conflict explanation=%q", explanation)
	}
}
