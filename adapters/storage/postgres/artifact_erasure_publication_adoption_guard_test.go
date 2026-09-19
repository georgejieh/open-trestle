package postgres

import (
	"bytes"
	"github.com/georgejieh/open-trestle/artifact"
	"testing"
	"time"
)

func TestResumeJournalPublicationAdoptsOriginalWithFreshProof(t *testing.T) {
	g := newResumeJournalFixture(t)
	admission, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "journal-protocol", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	intentKey, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), resumePrefix+"/deletions/"+op.Scope().Identity()+"/"+op.ArtifactIdentity()+".intent-v2")
	if err != nil {
		t.Fatal(err)
	}
	_, intentAbsent := resumeJournalRead(t, g, op, a, artifact.AttemptIntentRead, intentKey, "intent-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptIntentCreate, intentKey, resumeOperationBytes(t, op), intentAbsent, "intent-create")
	resumeJournalRead(t, g, op, a, artifact.AttemptIntentRead, intentKey, "intent-full")
	readAttempt, current := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "current-payload")
	currentOptions, err := artifact.ParseAttemptResponseEvidence(current, readAttempt)
	if err != nil {
		t.Fatal(err)
	}
	deletion := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionDelete, Key: g.Key(), Version: currentOptions.Version, ObservationIdentity: current.Identity(), MaximumResponseBytes: 4096}, "delete-payload")
	outcome, err := g.backend.DeleteObjectVersion(g.Context("delete-payload"), g.Key(), resumeOwner, currentOptions.Version)
	if err != nil || outcome != artifact.VersionDeleteDeleted {
		t.Fatal("owned exact-version deletion", err)
	}
	deleted, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: deletion, Code: artifact.AttemptResponseDeleted, ObservedAt: g.clock.Value()})
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, deleted)
	_, absent := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "current-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptFenceCreate, g.Key(), resumeFenceBytes(t, op), absent, "create-fence")
	_, observed := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "read-fence")
	fence, err := artifact.NewFenceObservationEvidence(op, g.Key(), observed, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), g.Key().Key()+".wrong")
	if err != nil {
		t.Fatal(err)
	}
	wrongFence, err := artifact.NewFenceObservationEvidence(op, wrongKey, observed, g.clock.Value())
	if err != nil {
		t.Fatal("valid metadata wrong-key fixture", err)
	}
	refused, inserted, err := g.journal.RecordErasureEvidence(g.Context("wrong-fence-key"), op.Ref(), wrongFence)
	if err == nil || inserted || refused.Identity() != "" {
		t.Fatal("fence record key differed from current request and derived key")
	}
	fence = resumeJournalRecord(t, g, op, fence)
	g.clock.Set(g.clock.Value().Add(time.Millisecond))
	laterFence, err := artifact.NewFenceObservationEvidence(op, g.Key(), observed, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	winner, inserted, err := g.journal.RecordErasureEvidence(g.Context("fence-cas"), op.Ref(), laterFence)
	if err != nil || inserted || winner.Identity() != fence.Identity() || !winner.ObservedAt().Equal(fence.ObservedAt()) {
		t.Fatal("same token fence did not adopt original winner", err)
	}
	_, list := resumeJournalList(t, g, op, a, "terminal-list", 2, artifact.VersionCursor{})
	_, full := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "terminal-current")
	verification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, full, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.NewVerificationEvidence(verification)
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, verified)
	candidate, err := artifact.NewAttestationCandidateEvidence(op, admission, g.policy, verification)
	if err != nil {
		t.Fatal(err)
	}
	candidate = resumeJournalRecord(t, g, op, candidate)
	g.clock.Set(g.clock.Value().Add(time.Millisecond))
	_, list2 := resumeJournalList(t, g, op, a, "second-terminal-list", 2, artifact.VersionCursor{})
	_, full2 := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "second-terminal-current")
	secondVerification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list2}, full2, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	secondVerified, err := artifact.NewVerificationEvidence(secondVerification)
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, secondVerified)
	secondCandidate, err := artifact.NewAttestationCandidateEvidence(op, admission, g.policy, secondVerification)
	if err != nil {
		t.Fatal(err)
	}
	winner, inserted, err = g.journal.RecordErasureEvidence(g.Context("candidate-cas"), op.Ref(), secondCandidate)
	if err != nil || inserted || winner.Identity() != candidate.Identity() || !bytes.Equal(winner.RecordBytes(), candidate.RecordBytes()) {
		t.Fatal("candidate winner changed", err)
	}
	key, err := artifact.NewExactObjectKey(g.policy.NamespaceIdentity(), resumePrefix+"/deletions/"+g.scope.Identity()+"/"+g.value.Identity()+".attestation-v2")
	if err != nil {
		t.Fatal(err)
	}
	_, proofAbsent := resumeJournalRead(t, g, op, a, artifact.AttemptAttestationRead, key, "proof-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptAttestationCreate, key, candidate.RecordBytes(), proofAbsent, "proof-create")
	_, proof := resumeJournalRead(t, g, op, a, artifact.AttemptAttestationRead, key, "proof-full-read")
	publication, err := artifact.NewAttestationPublicationEvidence(candidate, proof, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	publication = resumeJournalRecord(t, g, op, publication)
	progress, found, err := g.journal.ReadErasureProgress(g.Context("complete-closure"), op.Ref(), a.Identity())
	if err != nil || !found || progress.Validate() != nil {
		t.Fatal("durable publication closure", err)
	}
	got, ok := progress.Published()
	if !ok || got.Identity() != publication.Identity() {
		t.Fatal("publication preimage missing")
	}
	got, ok = progress.Candidate()
	if !ok || got.Identity() != candidate.Identity() {
		t.Fatal("original candidate missing")
	}
	for _, response := range []artifact.ErasureEvidence{observed, list, full, proof} {
		present := false
		for _, e := range progress.Evidence() {
			present = present || e.Identity() == response.Identity()
		}
		if !present {
			t.Fatal("mandatory evidence dependency omitted")
		}
	}

	g.clock.Set(g.clock.Value().Add(time.Millisecond))
	_, freshProof := resumeJournalRead(t, g, op, a, artifact.AttemptAttestationRead, key, "fresh-proof-read")
	freshPublication, err := artifact.NewAttestationPublicationEvidence(candidate, freshProof, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	if freshPublication.Identity() == publication.Identity() {
		t.Fatal("fresh proof read did not produce independent publication metadata")
	}
	revision := g.sql.Snapshot().Revision
	adopted, added, adoptErr := g.journal.RecordErasureEvidence(g.Context("adopt-original-publication"), op.Ref(), freshPublication)
	if adoptErr != nil || added || adopted.Identity() != publication.Identity() || !adopted.ObservedAt().Equal(publication.ObservedAt()) {
		t.Fatalf("same candidate and proof must adopt original publication: err=%v inserted=%v original_identity=%v", adoptErr, added, adopted.Identity() == publication.Identity())
	}
	if g.sql.Snapshot().Revision != revision {
		t.Fatal("publication adoption wrote another durable row")
	}
}
