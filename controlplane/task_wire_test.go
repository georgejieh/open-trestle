package controlplane

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestTaskLeaseEncodingRoundTripsExactCapability(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-a", time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTaskLease(lease)
	if err != nil || !bytes.Contains(encoded, []byte(lease.token)) {
		t.Fatalf("encoded=(%s,%v)", encoded, err)
	}
	parsed, err := ParseTaskLease(encoded)
	if err != nil || parsed.Identity() != lease.Identity() || parsed.token != lease.token || !bytes.Equal(encoded, mustEncodeTaskLease(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	if got, err := ParseTaskLease(unknown); err == nil || got.Identity() != "" {
		t.Fatalf("unknown=(%#v,%v)", got, err)
	}
}
func TestTaskCompletionEncodingRoundTripsClosedOutcomes(t *testing.T) {
	success, _ := NewTaskSuccess(strings.Repeat("e", 64))
	failure, _ := NewTaskFailure(RunFailureResourceLimit)
	for _, completion := range []TaskCompletion{success, failure} {
		encoded, err := EncodeTaskCompletion(completion)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseTaskCompletion(encoded)
		if err != nil || parsed.Identity() != completion.Identity() || parsed.Status() != completion.Status() || parsed.Failure() != completion.Failure() || !bytes.Equal(encoded, mustEncodeTaskCompletion(t, parsed)) {
			t.Fatalf("parsed=(%#v,%v)", parsed, err)
		}
	}
}
func mustEncodeTaskLease(t *testing.T, lease TaskLease) []byte {
	t.Helper()
	encoded, err := EncodeTaskLease(lease)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func mustEncodeTaskCompletion(t *testing.T, completion TaskCompletion) []byte {
	t.Helper()
	encoded, err := EncodeTaskCompletion(completion)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
