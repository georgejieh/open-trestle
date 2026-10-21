//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func testGenerationRejectionJournal(t *testing.T, fact controlplane.HistoricalContextPacketFact, auditEvents []audit.Event, now time.Time) {
	t.Helper()
	events := fact.ReplayEvents()
	if err := validateGenerationRejectionJournal(fact, events, auditEvents, now); err != nil {
		t.Fatalf("actual rejection journal refused: %v", err)
	}
	for i := range events {
		changed := append([]controlplane.RunEvent(nil), events...)
		changed[i] = controlplane.RunEvent{}
		if err := validateGenerationRejectionJournal(fact, changed, auditEvents, now); err == nil {
			t.Fatalf("invalid replay event %d admitted", i)
		}
	}
	if err := validateGenerationRejectionJournal(fact, events[:len(events)-1], auditEvents, now); err == nil {
		t.Fatal("missing terminal admitted")
	}
	if err := validateGenerationRejectionJournal(controlplane.HistoricalContextPacketFact{}, events, auditEvents, now); err == nil {
		t.Fatal("missing fact admitted")
	}
	if err := validateGenerationRejectionJournal(fact, events, nil, now); err == nil {
		t.Fatal("missing audit admitted")
	}
	if err := validateGenerationRejectionJournal(fact, events, auditEvents, events[len(events)-1].OccurredAt().Add(-time.Millisecond)); err == nil {
		t.Fatal("future terminal admitted")
	}
	late := append([]audit.Event(nil), auditEvents...)
	last := late[len(late)-1]
	changed, err := audit.NewEvent(last.Scope(), last.Sequence(), last.PreviousIdentity(), last.Kind(), last.SubjectIdentity(), last.CausalParentIdentities(), events[len(events)-1].OccurredAt().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	late[len(late)-1] = changed
	if err := validateGenerationRejectionJournal(fact, events, late, now.Add(time.Second)); err == nil {
		t.Fatal("rejection after failure admitted")
	}

	// Rebuild only the ordinary tail. Prepared v4/v5/v6 prefix events retain
	// their canonical descriptors, and the real file journal validates each stream.
	variant := func(renew bool, failure controlplane.RunFailure) (controlplane.HistoricalContextPacketFact, []controlplane.RunEvent) {
		t.Helper()
		plan := fact.Plan()
		result := make([]controlplane.RunEvent, 0, len(events)+1)
		previous := ""
		for _, event := range events {
			if event.Kind() == controlplane.RunEventTaskFailed && event.TaskKey() == "candidates" && renew {
				claim := result[len(result)-1]
				task, _ := plan.Task("candidates")
				renewal, err := controlplane.NewRunEvent(plan, uint64(len(result)+1), previous, controlplane.RunEventTaskLeaseRenewed, task, claim.Attempt(), claim.LeaseTokenIdentity(), claim.WorkerIdentity(), claim.LeaseExpiresAt().Add(time.Millisecond), "", 0, time.Time{}, claim.OccurredAt())
				if err != nil {
					t.Fatal(err)
				}
				result, previous = append(result, renewal), renewal.Identity()
			}
			if event.Kind() == controlplane.RunEventTaskFailed || event.Kind() == controlplane.RunEventTaskSkipped || event.Kind() == controlplane.RunEventFailed {
				currentFailure := event.Failure()
				if currentFailure == controlplane.RunFailureInternal {
					currentFailure = failure
				}
				task, _ := plan.Task(event.TaskKey())
				current, err := controlplane.NewRunEvent(plan, uint64(len(result)+1), previous, event.Kind(), task, event.Attempt(), event.LeaseTokenIdentity(), event.WorkerIdentity(), event.LeaseExpiresAt(), event.OutputIdentity(), currentFailure, event.RetryAt(), event.OccurredAt())
				if err != nil {
					t.Fatal(err)
				}
				event = current
			}
			result, previous = append(result, event), event.Identity()
		}
		if _, err := controlplane.ReplayReviewRun(plan, result); err != nil {
			t.Fatalf("variant replay: %v", err)
		}
		journalRoot := filepath.Join(t.TempDir(), "journal")
		journal, err := controlplane.NewFileRunJournal(journalRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		ctx := context.Background()
		if err := journal.SavePlan(ctx, plan); err != nil {
			t.Fatal(err)
		}
		// Public Append correctly refuses owner-only v6. Install only this
		// synthetic canonical stream, then use the production diagnostic parser.
		var stream bytes.Buffer
		for _, event := range result {
			encoded, err := controlplane.EncodeRunEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			stream.Write(encoded)
			stream.WriteByte(10)
		}
		if err := os.WriteFile(filepath.Join(journalRoot, plan.Scope().Identity()+".run.jsonl"), stream.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		facts, err := journal.InspectHistoricalContextPackets(ctx)
		if err != nil || len(facts) != 1 {
			t.Fatalf("variant facts: %v", err)
		}
		return facts[0], result
	}
	renewedFact, renewedEvents := variant(true, controlplane.RunFailureInternal)
	if err := validateGenerationRejectionJournal(renewedFact, renewedEvents, auditEvents, now); err != nil {
		t.Fatalf("valid renewal refused: %v", err)
	}
	for _, failure := range []controlplane.RunFailure{controlplane.RunFailureInvalidInput, controlplane.RunFailurePolicy} {
		changedFact, changedEvents := variant(false, failure)
		if err := validateGenerationRejectionJournal(changedFact, changedEvents, auditEvents, now); err == nil {
			t.Fatal("different canonical failure admitted")
		}
	}
}
