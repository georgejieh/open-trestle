package postgres

import (
	"bytes"
	"errors"
	"net/url"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestBudgetedResumeLostVersionListReplyRequiresExplicitRecovery(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	payloadKey := g.Key().Key()
	g.peer.AddHistory(t, payloadKey, false, []byte("synthetic legacy payload one"))
	g.peer.AddHistory(t, payloadKey, false, []byte("synthetic legacy payload two"))
	g.peer.AddHistory(t, payloadKey, true, nil)
	if history := g.peer.History(payloadKey); len(history) != 4 || !history[len(history)-1].Marker {
		t.Fatal("small real history was not current-marker over three data versions")
	}

	firstAllowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "lost-list-original", resumeMaximum())
	g.peer.Fault(resumePeerFault{Graph: g.name, Method: "GET", Key: payloadKey, Occurrence: 1, Lose: true, ListOnly: true})
	beforeFirst := len(g.peer.Events())
	result, err := g.store.ResumeErasure(g.ResumeContext("lost-list-original"), op.Ref(), firstAllowance)
	resumeZeroResult(t, result, err)
	if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
		t.Fatal("lost version-list reply was not public uncertainty", err)
	}

	lostList := resumeLostListEvent(t, g.peer.Events()[beforeFirst:], payloadKey)
	if lostList.Attempt == "" {
		t.Fatal("lost list had no durable attempt binding")
	}
	for _, event := range g.peer.Events()[beforeFirst:] {
		if event.Method == "DELETE" && event.Key == payloadKey {
			t.Fatal("first invocation used a lost version-list reply as deletion authority")
		}
	}
	afterLostHistory := g.peer.History(payloadKey)
	if len(afterLostHistory) != 5 || !bytes.Equal(afterLostHistory[len(afterLostHistory)-1].Body, resumeExpectedFence(t, op)) {
		t.Fatal("lost-list invocation should only add the independently read-back fence")
	}

	firstProgress, found, readErr := g.journal.ReadErasureProgress(g.Context("lost-list-progress"), op.Ref(), firstAllowance.Identity())
	if readErr != nil || !found {
		t.Fatal("first progress after lost list", readErr)
	}
	firstUsage := resumeSingleUsage(t, firstProgress, firstAllowance)
	if firstUsage.Spent.Lists != 1 || firstUsage.Spent.Pages != 1 || firstUsage.Spent.Versions < 2 || firstUsage.NextSequence != uint64(firstUsage.Spent.Requests)+1 {
		t.Fatal("lost list did not preserve requested allowance list spending")
	}
	snapshot := g.sql.Snapshot()
	resumeAssertLostListUncertainty(t, g, op, firstAllowance, snapshot, lostList, "lost-list-original")
	resumeAssertAllowanceUsageMatchesAttempts(t, g, snapshot, firstAllowance, firstUsage)

	freshAllowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "lost-list-fresh-recovery", resumeMaximum())
	beforeRecovery := len(g.peer.Events())
	result, err = g.store.ResumeErasure(g.ResumeContext("lost-list-recovery"), op.Ref(), freshAllowance)
	attestation := assertResumeCertified(t, g, op, result, err)
	if !result.HasUnknownHistory() {
		t.Fatal("certified recovery dropped the original unknown history")
	}
	if usage, ok := result.Usage(); !ok || usage.AllowanceIdentity != freshAllowance.Identity() || usage.Spent.Lists == 0 || usage.Spent.Deletes == 0 {
		t.Fatal("certified recovery did not use the fresh explicit allowance")
	}
	if !resumeRecoveryUsedVersionProofs(g.peer.Events()[beforeRecovery:], payloadKey, resumeAttestationKey(g.resumeJournalGraph)) {
		t.Fatal("fresh recovery did not execute the real list/current/proof sequence")
	}
	recoverySnapshot := g.sql.Snapshot()
	resumeAssertDeletesUseCommittedUsableObservations(t, g, op, recoverySnapshot, g.peer.Events()[beforeRecovery:])
	if count := resumePeerAttemptDispatches(g.peer.Events(), lostList.Attempt); count != 1 {
		t.Fatal("lost version-list attempt was replayed", count)
	}

	firstProgressAfter, found, readErr := g.journal.ReadErasureProgress(g.Context("original-usage-after-recovery"), op.Ref(), firstAllowance.Identity())
	if readErr != nil || !found {
		t.Fatal("original allowance progress after recovery", readErr)
	}
	firstUsageAfter := resumeSingleUsage(t, firstProgressAfter, firstAllowance)
	if firstUsageAfter != firstUsage {
		t.Fatal("fresh recovery refunded or replayed original allowance spending", firstUsage, firstUsageAfter)
	}

	g.peer.Stop(t)
	events, samples, kms, revision := len(g.peer.Events()), g.clock.Samples(), g.peer.KMSCount(g.name), g.sql.Snapshot().Revision
	read, found, readErr := g.store.ReadErasure(g.Context("db-only-certified-read"), op.Ref())
	if readErr != nil || !found || read.State() != artifact.ErasureStateCertified || !read.HasUnknownHistory() {
		t.Fatal("DB-only certified read did not retain unknown history", readErr, found, read.State())
	}
	storedAttestation, ok := read.Attestation()
	if !ok {
		t.Fatal("DB-only certified read missing attestation")
	}
	want, wantErr := artifact.EncodeErasureAttestationV2(attestation)
	got, gotErr := artifact.EncodeErasureAttestationV2(storedAttestation)
	if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		t.Fatal("DB-only certified read changed attestation", wantErr, gotErr)
	}
	if len(g.peer.Events()) != events || g.clock.Samples() != samples || g.peer.KMSCount(g.name) != kms || g.sql.Snapshot().Revision != revision {
		t.Fatal("ReadErasure performed work outside the DB snapshot")
	}
}

func resumeLostListEvent(t *testing.T, events []resumeWireEvent, key string) resumeWireEvent {
	t.Helper()
	var found resumeWireEvent
	for _, event := range events {
		query, err := url.ParseQuery(event.Query)
		if err != nil {
			t.Fatal("wire query parse", err)
		}
		if event.Method == "GET" && event.Key == key && query.Has("versions") {
			if found.Attempt != "" {
				t.Fatal("fault should stop the first invocation at the first version-list request")
			}
			found = event
		}
	}
	if found.Attempt == "" {
		t.Fatal("first invocation did not reach the faulted version-list request")
	}
	return found
}

func resumeRecoveryUsedVersionProofs(events []resumeWireEvent, payloadKey, proofKey string) bool {
	terminalList, currentAfterTerminal, proofRead := false, false, false
	for _, event := range events {
		query, _ := url.ParseQuery(event.Query)
		if event.Method == "GET" && event.Key == payloadKey && query.Has("versions") && query.Get("max-keys") == "2" && query.Get("key-marker") == "" && query.Get("version-id-marker") == "" {
			terminalList = true
			currentAfterTerminal = false
			continue
		}
		if terminalList && event.Method == "GET" && event.Key == payloadKey && event.Query == "" {
			currentAfterTerminal = true
		}
		if event.Method == "GET" && event.Key == proofKey && event.Query == "" && event.Attempt != "" {
			proofRead = true
		}
	}
	return terminalList && currentAfterTerminal && proofRead
}

func resumePeerAttemptDispatches(events []resumeWireEvent, attemptID string) int {
	count := 0
	for _, event := range events {
		if event.Attempt == attemptID {
			count++
		}
	}
	return count
}
