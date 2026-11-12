package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// modelTaskLease succeeds every task before key and claims key at at.
func modelTaskLease(t *testing.T, c *Coordinator, plan ReviewRunPlan, key string, at int64) TaskLease {
	t.Helper()
	ctx := context.Background()
	order := []string{"source", "change", "analysis", "memory", "context", "candidates", "verification"}
	for _, before := range order {
		if before == key {
			break
		}
		task, _ := plan.Task(before)
		lease, ok, err := c.ClaimTask(ctx, plan, before, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", before, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err = c.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1)); err != nil {
			t.Fatalf("complete %s: %v", before, err)
		}
		at += 20
	}
	task, _ := plan.Task(key)
	lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatalf("claim %s: %v", key, err)
	}
	return lease
}

var providerRefusalReasons = []struct {
	reason  TaskFailureReason
	token   string
	failure RunFailure
}{
	{TaskFailureReasonProviderPaymentRequired, "provider_payment_required", RunFailurePolicy},
	{TaskFailureReasonProviderModelUnavailable, "provider_model_unavailable", RunFailurePolicy},
	{TaskFailureReasonProviderModelRetired, "provider_model_retired", RunFailurePolicy},
	{TaskFailureReasonProviderAuthenticationFailed, "provider_authentication_failed", RunFailurePolicy},
	{TaskFailureReasonProviderAuthorizationDenied, "provider_authorization_denied", RunFailurePolicy},
	{TaskFailureReasonProviderRateLimited, "provider_rate_limited", RunFailureTransient},
	{TaskFailureReasonProviderResponseInvalid, "provider_response_invalid", RunFailureInternal},
	{TaskFailureReasonModelOutputInvalid, "model_output_invalid", RunFailureInternal},
}

// A model task records the provider's refusal as a closed, content-free
// reason that survives the durable journal, replay, the receipt and the
// worker wire, with the one run failure each reason names.
func TestModelTaskProviderRefusalIsRecordedAndReadBack(t *testing.T) {
	ctx := context.Background()
	schemas := filepath.Join("..", "schemas", "controlplane")
	for _, test := range providerRefusalReasons {
		for _, key := range []string{"candidates", "verification"} {
			t.Run(test.token+"/"+key, func(t *testing.T) {
				if parsed, err := ParseTaskFailureReason(test.token); err != nil || parsed != test.reason || test.reason.String() != test.token {
					t.Fatalf("token %q = (%v, %v)", test.token, parsed, err)
				}
				root := t.TempDir()
				journal, err := NewFileRunJournal(root)
				if err != nil {
					t.Fatal(err)
				}
				plan := inventoryPlan(t, "tenant", "repository", "run-provider-"+key)
				coordinator := inventoryOpen(t, journal, plan)
				lease := modelTaskLease(t, coordinator, plan, key, 200)
				task, _ := plan.Task(key)
				completion, err := NewModelTaskFailureWithReason(test.failure, test.reason, plan, task)
				if err != nil || completion.Validate() != nil || completion.FailureReason() != test.reason {
					t.Fatalf("completion: %v", err)
				}
				encodedCompletion, err := EncodeTaskCompletion(completion)
				if err != nil || !bytes.Contains(encodedCompletion, []byte(`"schema_version":3`)) || !bytes.Contains(encodedCompletion, []byte(`"failure_reason":"`+test.token+`"`)) {
					t.Fatalf("completion wire=%s err=%v", encodedCompletion, err)
				}
				if parsed, err := ParseTaskCompletion(encodedCompletion); err != nil || parsed.Identity() != completion.Identity() {
					t.Fatalf("completion readback: %v", err)
				}
				if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(lease.ExpiresAt().UnixMilli()-1)); err != nil {
					t.Fatal(err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := NewFileRunJournal(root)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				readback, _ := NewCoordinator(reopened)
				_, state, err := readback.Resume(ctx, plan.Scope())
				if err != nil {
					t.Fatal(err)
				}
				runtime, _ := state.Task(key)
				if runtime.Status() != TaskRuntimeFailed || runtime.Failure() != test.failure || runtime.FailureReason() != test.reason {
					t.Fatalf("replayed %s failure=%s reason=%s", runtime.Status(), runtime.Failure(), runtime.FailureReason())
				}
				events, _ := reopened.Read(ctx, plan.Scope(), 0, 100)
				encodedEvent, err := EncodeRunEvent(events[len(events)-1])
				if err != nil || !bytes.Contains(encodedEvent, []byte(`"schema_version":7`)) || !bytes.Contains(encodedEvent, []byte(`"failure_reason":"`+test.token+`"`)) {
					t.Fatalf("event=%s err=%v", encodedEvent, err)
				}
				receipt, err := NewReviewRunReceipt(state)
				if err != nil {
					t.Fatal(err)
				}
				encodedReceipt, err := EncodeReviewRunReceipt(receipt)
				if err != nil {
					t.Fatal(err)
				}
				parsedReceipt, err := ParseReviewRunReceipt(encodedReceipt)
				if err != nil || parsedReceipt.Identity() != receipt.Identity() {
					t.Fatalf("receipt readback: %v", err)
				}
				if task, _ := parsedReceipt.Task(key); task.FailureReason() != test.reason {
					t.Fatal("receipt lost the reason")
				}
				assertSchemaRecordShape(t, filepath.Join(schemas, "review-task-completion-v3.schema.json"), encodedCompletion)
				assertSchemaRecordShape(t, filepath.Join(schemas, "review-run-event-v7.schema.json"), encodedEvent)
				assertSchemaRecordShape(t, filepath.Join(schemas, "review-run-receipt-v3.schema.json"), encodedReceipt)
			})
		}
	}
}

// A provider refusal belongs to a model task and its one run failure; it is
// refused on any other task, with any other failure, or with counts.
func TestProviderRefusalReasonIsModelTaskOnly(t *testing.T) {
	plan := inventoryPlan(t, "tenant", "repository", "run-provider-scope")
	candidates, _ := plan.Task("candidates")
	for _, test := range providerRefusalReasons {
		for _, key := range []string{"source", "context", "readiness"} {
			other, _ := plan.Task(key)
			if _, err := NewModelTaskFailureWithReason(test.failure, test.reason, plan, other); !errors.Is(err, ErrInvalidTaskCompletion) {
				t.Fatalf("%s on %s err=%v", test.token, key, err)
			}
		}
		for _, failure := range []RunFailure{RunFailureTransient, RunFailurePolicy, RunFailureInternal, RunFailureResourceLimit} {
			if failure == test.failure {
				continue
			}
			if _, err := NewModelTaskFailureWithReason(failure, test.reason, plan, candidates); !errors.Is(err, ErrInvalidTaskCompletion) {
				t.Fatalf("%s with %s err=%v", test.token, failure, err)
			}
		}
		if _, err := NewSourceTaskFailureWithReason(test.failure, test.reason, plan, candidates); !errors.Is(err, ErrInvalidTaskCompletion) {
			t.Fatalf("%s through the source constructor err=%v", test.token, err)
		}
		if _, err := NewContextTaskRefusal(test.reason, TaskFailureContextShortfall{}, plan, candidates); !errors.Is(err, ErrInvalidTaskCompletion) {
			t.Fatalf("%s through the context constructor err=%v", test.token, err)
		}
	}
	for _, reason := range []TaskFailureReason{0, TaskFailureReasonNoMergeBase, TaskFailureReasonNoEligibleRoute, TaskFailureReasonModelOutputInvalid + 1} {
		if _, err := NewModelTaskFailureWithReason(RunFailurePolicy, reason, plan, candidates); !errors.Is(err, ErrInvalidTaskCompletion) {
			t.Fatalf("reason %d accepted on a model task err=%v", reason, err)
		}
	}
	if _, err := ParseTaskFailureReason("provider_unknown"); err == nil {
		t.Fatal("unknown provider reason parsed")
	}
}

// providerSchemaRecords returns the encoded completion, events and receipt of
// one run whose candidates task records reason with failure.
func providerSchemaRecords(t *testing.T, reason TaskFailureReason, failure RunFailure) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := inventoryPlan(t, "tenant", "repository", "run-schema-"+reason.String())
	coordinator := inventoryOpen(t, journal, plan)
	lease := modelTaskLease(t, coordinator, plan, "candidates", 200)
	task, _ := plan.Task("candidates")
	completion, err := NewModelTaskFailureWithReason(failure, reason, plan, task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(lease.ExpiresAt().UnixMilli()-1)); err != nil {
		t.Fatal(err)
	}
	records := map[string][]byte{}
	if records["completion"], err = EncodeTaskCompletion(completion); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		if records[fmt.Sprintf("event-%02d", i)], err = EncodeRunEvent(event); err != nil {
			t.Fatal(err)
		}
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

// Every record of a run whose model task records a provider refusal
// validates against its versioned schema, and the schemas refuse the reason
// with another failure, with counts, on a context task, or unknown.
func TestProviderRefusalRecordsValidateAgainstSchemas(t *testing.T) {
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	counts := []byte(`,"context_shortfall":{"required_tokens":14096,"estimated_input_tokens":10000,"max_output_tokens":4096,"declared_context_tokens":8192}`)
	for _, test := range providerRefusalReasons {
		t.Run(test.token, func(t *testing.T) {
			other := RunFailurePolicy
			if test.failure == RunFailurePolicy {
				other = RunFailureTransient
			}
			marker := []byte(`"failure_reason":"` + test.token + `"`)
			reasoned := 0
			for name, encoded := range providerSchemaRecords(t, test.reason, test.failure) {
				id := recordSchemaID(t, name, encoded)
				if err := registry.Validate(id, encoded); err != nil {
					t.Fatalf("%s (%s): %v\n%s", name, id, err, encoded)
				}
				if !bytes.Contains(encoded, marker) {
					continue
				}
				reasoned++
				failure := []byte(`"failure":"` + test.failure.String() + `"`)
				forgeries := [][]byte{
					bytes.Replace(encoded, marker, append(append([]byte{}, marker...), counts...), 1),
					bytes.Replace(encoded, marker, []byte(`"failure_reason":"provider_unknown"`), 1),
				}
				if name == "receipt" {
					forgeries = append(forgeries, bytes.Replace(encoded, []byte(`"kind":"generate_candidates"`), []byte(`"kind":"assemble_context"`), 1))
				}
				// A receipt names its run failure before its tasks; forge the
				// last occurrence, which is the reasoned task's own.
				if index := bytes.LastIndex(encoded, failure); index >= 0 {
					forged := append(append(append([]byte{}, encoded[:index]...), []byte(`"failure":"`+other.String()+`"`)...), encoded[index+len(failure):]...)
					forgeries = append(forgeries, forged)
				}
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
