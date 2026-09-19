package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/keys/awskms"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

type budgetedResumeGraph struct {
	*resumeJournalGraph
	store       *IndexedArtifactStore
	invocations map[string]bool
}

type budgetedResumeClock struct {
	mu                     sync.Mutex
	base                   *resumeClock
	initial, started, last time.Time
}

func (c *budgetedResumeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	at := c.base.Now()
	if !at.Equal(c.last) {
		return at
	}
	at = c.initial.Add(time.Since(c.started).Truncate(time.Millisecond))
	c.base.Set(at)
	c.last = at
	return at
}

func newBudgetedResumeGraph(t *testing.T, g *resumeJournalGraph) *budgetedResumeGraph {
	t.Helper()
	before, wire, samples := len(g.sql.Snapshot().Events), len(g.peer.Events()), g.clock.Samples()
	clock := &budgetedResumeClock{base: g.clock, initial: g.clock.Value(), last: g.clock.Value(), started: time.Now()}
	store, err := NewIndexedBudgetedEnvelopeStore(g.index, BudgetedEnvelopeDependencies{Backend: g.backend, Keys: g.keys, Clock: clock, IndexAuthority: g.witness}, g.policy)
	if err != nil {
		t.Fatal("indexed budgeted factory", err)
	}
	if len(g.sql.Snapshot().Events) != before || len(g.peer.Events()) != wire || g.clock.Samples() != samples {
		t.Fatal("budgeted constructor performed work")
	}
	wrapped := &budgetedResumeGraph{resumeJournalGraph: g, store: store, invocations: map[string]bool{}}
	t.Cleanup(func() { wrapped.assertInvocationBudgets(t) })
	return wrapped
}
func (g *budgetedResumeGraph) Prepared() (artifact.ArtifactAdmission, artifact.ErasureOperation, artifact.ErasureAuthorizationV2) {
	t := g.t
	t.Helper()
	ok, err := g.store.Put(g.Context("put"), g.value, g.clock.Value())
	if err != nil || !ok {
		t.Fatal("public indexed Put", err)
	}
	got, err := g.store.Get(g.Context("get"), g.scope, g.value.Identity(), g.clock.Value())
	if err != nil || !bytes.Equal(got.Payload(), g.value.Payload()) {
		t.Fatal("public indexed Get", err)
	}
	a, found, err := g.store.ReadAdmission(g.Context("admission"), g.scope, g.policy.NamespaceIdentity(), g.value.Identity())
	if err != nil || !found {
		t.Fatal(err)
	}
	grant := resumeGrant(t, g.policy, a, g.clock.Value())
	return a, g.prepare(a, grant), grant
}
func (g *budgetedResumeGraph) prepare(a artifact.ArtifactAdmission, grant artifact.ErasureAuthorizationV2) artifact.ErasureOperation {
	t := g.t
	t.Helper()
	before, kms := len(g.peer.Events()), g.peer.KMSCount(g.name)
	op, err := g.store.PrepareErasure(g.Context("prepare"), grant, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.peer.Events()) != before || g.peer.KMSCount(g.name) != kms {
		t.Fatal("Prepare performed remote work")
	}
	if _, err := g.store.Get(g.Context("deleted-get"), g.scope, g.value.Identity(), g.clock.Value()); !errors.Is(err, artifact.ErrArtifactDeleted) {
		t.Fatal("prepared Get", err)
	}
	g.peer.DisableKMS(g.name)
	return op
}
func resumeZeroResult(t *testing.T, r artifact.ErasureResult, err error) {
	t.Helper()
	if err == nil || r.State() != 0 || r.Operation().Identity() != "" {
		t.Fatal("error returned nonzero result", err)
	}
	if _, ok := r.Attestation(); ok {
		t.Fatal("error carried attestation")
	}
	if _, ok := r.Usage(); ok {
		t.Fatal("error carried usage")
	}
}
func resumeExpectedFence(t *testing.T, op artifact.ErasureOperation) []byte {
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-fence", "schema_version": 1, "erasure_protocol": "same-key-fence-v2", "namespace_identity": op.NamespaceIdentity(), "scope_identity": op.Scope().Identity(), "artifact_identity": op.ArtifactIdentity(), "operation_identity": op.Identity(), "prepared_at_milliseconds": op.PreparedAt().UnixMilli()}
	return append([]byte("OTAF0001"), resumeOrdered(t, fields, "contract schema_version identity erasure_protocol namespace_identity scope_identity artifact_identity operation_identity prepared_at_milliseconds", "open-trestle/artifact-erasure-fence/v1\x00")...)
}
func resumeAttestationKey(g *resumeJournalGraph) string {
	return resumePrefix + "/deletions/" + g.scope.Identity() + "/" + g.value.Identity() + ".attestation-v2"
}
func resumeIntentKey(g *resumeJournalGraph) string {
	return strings.TrimSuffix(resumeAttestationKey(g), ".attestation-v2") + ".intent-v2"
}
func assertResumeCertified(t *testing.T, g *budgetedResumeGraph, op artifact.ErasureOperation, r artifact.ErasureResult, err error, selected ...artifact.ProtectedErasurePolicy) artifact.ErasureAttestationV2 {
	t.Helper()
	if err != nil || r.State() != artifact.ErasureState(5) || r.Operation().Identity() != op.Identity() {
		t.Fatal("actual Resume did not complete", err, r.State())
	}
	attestation, ok := r.Attestation()
	if !ok || attestation.Validate() != nil {
		t.Fatal("Certified without attestation")
	}
	if attestation.OperationIdentity() != op.Identity() || attestation.OriginalAuthorizationIdentity() != op.OriginalAuthorizationIdentity() || attestation.PreparedAt() != op.PreparedAt() || attestation.RemainingDataVersions() != 1 || attestation.RemainingDeleteMarkers() != 0 {
		t.Fatal("attestation bindings")
	}
	history := g.peer.History(g.Key().Key())
	if len(history) != 1 || history[0].Marker || !bytes.Equal(history[0].Body, resumeExpectedFence(t, op)) {
		t.Fatal("permanent same-key fence did not replace every payload/marker token")
	}
	proof := g.peer.History(resumeAttestationKey(g.resumeJournalGraph))
	if len(proof) != 1 || proof[0].Marker {
		t.Fatal("immutable proof missing")
	}
	raw, err := artifact.EncodeErasureAttestationV2(attestation)
	if err != nil || !bytes.Equal(raw, proof[0].Body) {
		t.Fatal("published full proof bytes", err)
	}
	rows := g.sql.Snapshot().Rows[resumeEvidence]
	candidate, published := false, false
	for _, row := range rows {
		if row["slot"] == "candidate" {
			candidate = true
		}
		if row["slot"] == "published" {
			published = true
			known := false
			for _, e := range g.sql.Snapshot().Events {
				if e.StatementID == "evidence_insert" && len(e.Arguments) == 14 && e.Arguments[9] == "published" && resumeCommitted(g.sql.Snapshot().Events, e.Graph, e.OperationLabel, e.TransactionID) {
					known = true
				}
			}
			if !known {
				t.Fatal("published state without known insertion commit")
			}
		}
	}
	if !candidate || !published {
		t.Fatal("missing durable candidate/publication")
	}
	var terminal, current *resumeWireEvent
	events := g.peer.Events()
	for i := range events {
		e := &events[i]
		if e.Graph != g.name || e.Header.Get("X-Amz-Expected-Bucket-Owner") == "" {
			continue
		}
		if e.Method == "DELETE" && e.Key == g.Key().Key() {
			q, _ := url.ParseQuery(e.Query)
			if q.Get("versionId") == history[0].ID {
				t.Fatal("required fence targeted by DELETE")
			}
		}
		q, _ := url.ParseQuery(e.Query)
		if e.Method == "GET" && e.Key == g.Key().Key() && q.Get("max-keys") == "2" && q.Get("key-marker") == "" && q.Get("version-id-marker") == "" {
			terminal = e
			current = nil
		}
		if terminal != nil && e.Method == "GET" && e.Key == g.Key().Key() && e.Query == "" && e.Sequence > terminal.Sequence {
			current = e
		}
	}
	if terminal == nil || current == nil || terminal.Attempt == "" || current.Attempt == "" || terminal.Attempt == current.Attempt || current.Sequence <= terminal.Sequence {
		t.Fatal("fresh empty-input limit2 list and separate current read missing")
	}
	policy := g.policy
	if len(selected) > 0 {
		policy = selected[0]
	}
	resumeAssertIndependentAttestation(t, g, op, attestation, policy, proof[0].Body)
	return attestation
}
func TestBudgetedResumeCompletesAndReopensFromExternalState(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	payloadKey := g.Key().Key()
	for i := 0; i < 9; i++ {
		g.peer.AddHistory(t, payloadKey, i%3 == 0, []byte(fmt.Sprintf("synthetic historical payload %d", i)))
	}
	g.peer.AddHistory(t, payloadKey, false, resumeExpectedFence(t, op))
	g.peer.AddHistory(t, payloadKey, true, nil)
	a, path, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "completion", resumeMaximum())
	kms := g.peer.KMSCount(g.name)
	result, err := g.store.ResumeErasure(g.ResumeContext("resume"), op.Ref(), a)
	attestation := assertResumeCertified(t, g, op, result, err)
	createdFence := false
	for _, event := range g.peer.Events() {
		if event.Graph == g.name && event.Method == "PUT" && event.Key == payloadKey && (event.ResponseStatus == 200 || event.ResponseStatus == 201) && bytes.Equal(event.Body, resumeExpectedFence(t, op)) && event.Attempt != "" {
			createdFence = true
		}
	}
	if !createdFence {
		t.Fatal("positive chain did not create its own same-key fence")
	}
	if g.peer.KMSCount(g.name) != kms {
		t.Fatal("Resume called KMS")
	}
	usage, err := g.journal.AdmitResumeAllowance(g.Context("usage"), op.Ref(), a, g.clock.Value())
	if err != nil || usage.Spent.Requests == 0 {
		t.Fatal("durable spend", err)
	}
	s, p, value, policy, at, oldWitness := g.sql, g.peer, g.value, g.policy, g.clock.Value(), g.witness
	if err := g.db.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := newResumeJournalGraph(t, s, p, value, policy, at, "reopened")
	before := len(s.Snapshot().Events)
	denied, err := NewIndexedBudgetedEnvelopeStore(fresh.index, BudgetedEnvelopeDependencies{Backend: fresh.backend, Keys: fresh.keys, Clock: fresh.clock, IndexAuthority: oldWitness}, policy)
	if err == nil || denied != nil || len(s.Snapshot().Events) != before {
		t.Fatal("old witness crossed database handles")
	}
	reopened := newBudgetedResumeGraph(t, fresh)
	reopened.peer.DisableKMS(reopened.name)
	reloaded, err := artifact.LoadResumeAllowance(context.Background(), path, policy, value.Scope())
	if err != nil {
		t.Fatal(err)
	}
	usage2, err := reopened.journal.AdmitResumeAllowance(reopened.Context("same-allowance"), op.Ref(), reloaded, at)
	if err != nil || usage2 != usage {
		t.Fatal("reopen reset allowance", err)
	}
	p.Stop(t)
	events, samples, kms := len(p.Events()), reopened.clock.Samples(), p.KMSCount(reopened.name)
	revision := s.Snapshot().Revision
	read, found, err := reopened.store.ReadErasure(reopened.Context("immutable-read"), op.Ref())
	if err != nil || !found || read.State() != artifact.ErasureState(5) {
		t.Fatal("DB-only reopened Read", err)
	}
	again, ok := read.Attestation()
	if !ok || !reflect.DeepEqual(again, attestation) {
		t.Fatal("historical attestation retimed or relabeled")
	}
	if len(p.Events()) != events || p.KMSCount(reopened.name) != kms || reopened.clock.Samples() != samples || s.Snapshot().Revision != revision {
		t.Fatal("immutable Read performed work outside DB snapshot")
	}
}
func TestBudgetedResumeUnknownPublicationDoesNotReplayAndRefreshPreservesCandidate(t *testing.T) {
	base := newResumeJournalFixture(t)
	at := base.clock.Value()
	short := resumePolicy(t, base.sql.catalog, base.backend, at, map[string]any{"not_after_milliseconds": at.Add(30 * time.Second).UnixMilli()})
	g := newBudgetedResumeGraph(t, newResumeJournalGraph(t, base.sql, base.peer, base.value, short, at, "short-authority"))
	ok, err := g.store.Put(g.Context("put"), g.value, at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	admission, found, err := g.store.ReadAdmission(g.Context("admission"), g.scope, g.policy.NamespaceIdentity(), g.value.Identity())
	if err != nil || !found {
		t.Fatal(err)
	}
	grant := resumeGrant(t, short, admission, at, at.Add(20*time.Second))
	op := g.prepare(admission, grant)
	a, _, _ := resumeAllowance(t, short, op, at, "original-issuance", resumeMaximum())
	proofKey := resumeAttestationKey(g.resumeJournalGraph)
	g.peer.Fault(resumePeerFault{Graph: g.name, Method: "PUT", Key: proofKey, Occurrence: 1, Lose: true})
	result, err := g.store.ResumeErasure(g.ResumeContext("unknown-proof"), op.Ref(), a)
	resumeZeroResult(t, result, err)
	if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
		t.Fatal("lost proof reply", err)
	}
	var original []byte
	for _, row := range g.sql.Snapshot().Rows[resumeEvidence] {
		if row["slot"] == "candidate" {
			original = append([]byte(nil), row["canonical_evidence"].([]byte)...)
		}
		if row["slot"] == "published" {
			t.Fatal("published before proof-read commit")
		}
	}
	if len(original) == 0 || len(g.peer.History(proofKey)) != 1 {
		t.Fatal("candidate or persisted proof missing")
	}
	freshAt := at.Add(31 * time.Second)
	freshPolicy := resumePolicy(t, g.sql.catalog, g.backend, freshAt, map[string]any{"configuration_evidence_identity": strings.Repeat("d", 64)})
	if err := g.db.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := newBudgetedResumeGraph(t, newResumeJournalGraph(t, g.sql, g.peer, g.value, freshPolicy, freshAt, "refresh"))
	fresh.peer.DisableKMS(fresh.name)
	next, _, _ := resumeAllowance(t, freshPolicy, op, freshAt, "explicit-new-issuance", resumeMaximum())
	result, err = fresh.store.ResumeErasure(fresh.ResumeContext("refresh"), op.Ref(), next)
	att := assertResumeCertified(t, fresh, op, result, err, short)
	for _, row := range fresh.sql.Snapshot().Rows[resumeEvidence] {
		if row["slot"] == "candidate" && !bytes.Equal(row["canonical_evidence"].([]byte), original) {
			t.Fatal("winner candidate changed after policy refresh")
		}
	}
	if att.ResumePolicyIdentity() != short.Identity() || att.ProtectedPolicyIdentity() != op.ProtectedPolicyIdentity() || att.ConfigurationEvidenceIdentity() != short.ConfigurationEvidenceIdentity() || !att.CompletedAt().Before(short.NotAfter()) {
		t.Fatal("refreshed policy relabeled historical candidate")
	}
	creates := 0
	for _, e := range fresh.peer.Events() {
		if e.Method == "PUT" && e.Key == proofKey {
			creates++
		}
	}
	if creates != 1 {
		t.Fatal("unknown publication replayed a create instead of observing")
	}
	if !result.HasUnknownHistory() {
		t.Fatal("unknown history disappeared")
	}
}
func TestBudgetedResumeMoreBookkeepingHasZeroOutbound(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		t.Run(fmt.Sprintf("distinct=%t", distinct), func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			selected, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "selected", resumeMaximum())
			if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-selected"), op.Ref(), selected, g.clock.Value()); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 129; i++ {
				active := g.resumeJournalGraph
				a := selected
				if distinct {
					p := resumePolicy(t, g.sql.catalog, g.backend, g.clock.Value(), map[string]any{"configuration_evidence_identity": resumeHash([]byte(fmt.Sprintf("history-%03d", i)))})
					active = newResumeJournalGraph(t, g.sql, g.peer, g.value, p, g.clock.Value(), fmt.Sprintf("historical-%03d", i))
					a, _, _ = resumeAllowance(t, p, op, g.clock.Value(), fmt.Sprintf("issuance-%03d", i), resumeMaximum())
					if _, err := active.journal.AdmitResumeAllowance(active.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
						t.Fatal(err)
					}
				}
				r := resumeCurrentRequest(t, active, op, a, fmt.Sprintf("reservation-%03d", i))
				if _, inserted, err := active.journal.ReserveErasureAttempt(active.Context("reserve"), op.Ref(), a, r, active.clock.Value()); err != nil || !inserted {
					t.Fatal("product reservation", err)
				}
			}
			for pass := 0; pass < 2; pass++ {
				before := len(g.peer.Events())
				kms := g.peer.KMSCount(g.name)
				result, err := g.store.ResumeErasure(g.ResumeContext(fmt.Sprintf("bookkeeping-%d", pass)), op.Ref(), selected)
				resumeZeroResult(t, result, err)
				if !errors.Is(err, artifact.ErrErasureUnknownOutcome) || len(g.peer.Events()) != before || g.peer.KMSCount(g.name) != kms {
					t.Fatal("More bookkeeping performed outbound work", err)
				}
				unknown := 0
				for _, row := range g.sql.Snapshot().Rows[resumeEvidence] {
					if row["kind"] == "unknown" {
						unknown++
					}
				}
				if unknown != (pass+1)*64 {
					t.Fatal("bookkeeping count", unknown)
				}
			}
			result, err := g.store.ResumeErasure(g.ResumeContext("remaining-and-converge"), op.Ref(), selected)
			assertResumeCertified(t, g, op, result, err)
			if !result.HasUnknownHistory() {
				t.Fatal("retained histories disappeared")
			}
		})
	}
}
func TestBudgetedResumeAbandonedPutNeedsNoCiphertext(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	g.peer.mu.Lock()
	g.peer.graphs[g.name].generateError = errors.New("synthetic KMS unavailable")
	g.peer.mu.Unlock()
	inserted, err := g.store.Put(g.Context("abandoned-put"), g.value, g.clock.Value())
	if err == nil || inserted || len(g.peer.History(g.Key().Key())) != 0 {
		t.Fatal("abandoned Put fixture")
	}
	a, found, err := g.store.ReadAdmission(g.Context("admission"), g.scope, g.policy.NamespaceIdentity(), g.value.Identity())
	if err != nil || !found {
		t.Fatal("actual admission absent", err)
	}
	op := g.prepare(a, resumeGrant(t, g.policy, a, g.clock.Value()))
	allowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "abandoned", resumeMaximum())
	result, err := g.store.ResumeErasure(g.ResumeContext("resume"), op.Ref(), allowance)
	assertResumeCertified(t, g, op, result, err)
}
func resumeWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(16 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		t.Fatal("external barrier not reached")
	}
}
func TestBudgetedResumePermanentFenceClosesDelayedAdmittedCreate(t *testing.T) {
	for _, when := range []string{"payload-wins-before-fence", "payload-loses-after-fence", "write-before-reply"} {
		t.Run(when, func(t *testing.T) {
			delayed := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			key := delayed.Key().Key()
			entered, release := make(chan struct{}), make(chan struct{})
			delayed.peer.Fault(resumePeerFault{Graph: delayed.name, Method: "PUT", Key: key, Occurrence: 1, Before: when != "write-before-reply", After: when == "write-before-reply", Entered: entered, Release: release})
			workers := newResumeWorkers(t)
			ctx := delayed.Context("delayed-put")
			type putReply struct {
				inserted bool
				err      error
			}
			putDone := make(chan putReply, 1)
			workers.Start(ctx, func(owned context.Context) {
				ok, err := delayed.store.Put(owned, delayed.value, delayed.clock.Value())
				putDone <- putReply{ok, err}
			})
			resumeWait(t, entered)
			resumer := newBudgetedResumeGraph(t, newResumeJournalGraph(t, delayed.sql, delayed.peer, delayed.value, delayed.policy, delayed.clock.Value(), "resumer"))
			a, found, err := resumer.store.ReadAdmission(resumer.Context("admission"), resumer.scope, resumer.policy.NamespaceIdentity(), resumer.value.Identity())
			if err != nil || !found {
				t.Fatal(err)
			}
			op := resumer.prepare(a, resumeGrant(t, resumer.policy, a, resumer.clock.Value()))
			allowance, _, _ := resumeAllowance(t, resumer.policy, op, resumer.clock.Value(), "race", resumeMaximum())
			var reply putReply
			if when == "payload-wins-before-fence" {
				fenceEntered, fenceRelease := make(chan struct{}), make(chan struct{})
				resumer.peer.Fault(resumePeerFault{Graph: resumer.name, Method: "PUT", Key: key, Occurrence: 1, Before: true, Entered: fenceEntered, Release: fenceRelease})
				type resultReply struct {
					r   artifact.ErasureResult
					err error
				}
				done := make(chan resultReply, 1)
				resumeCtx := resumer.ResumeContext("resume-race")
				workers.Start(resumeCtx, func(owned context.Context) {
					r, err := resumer.store.ResumeErasure(owned, op.Ref(), allowance)
					done <- resultReply{r, err}
				})
				resumeWait(t, fenceEntered)
				close(release)
				timer := time.NewTimer(16 * time.Second)
				select {
				case reply = <-putDone:
				case <-timer.C:
					t.Fatal("delayed Put did not return")
				}
				timer.Stop()
				close(fenceRelease)
				timer = time.NewTimer(16 * time.Second)
				select {
				case out := <-done:
					assertResumeCertified(t, resumer, op, out.r, out.err)
				case <-timer.C:
					t.Fatal("Resume race did not join")
				}
				timer.Stop()
			} else {
				result, err := resumer.store.ResumeErasure(resumer.ResumeContext("resume-race"), op.Ref(), allowance)
				assertResumeCertified(t, resumer, op, result, err)
				close(release)
				timer := time.NewTimer(16 * time.Second)
				select {
				case reply = <-putDone:
				case <-timer.C:
					t.Fatal("delayed Put did not return")
				}
				timer.Stop()
			}
			if reply.inserted && reply.err == nil {
				t.Fatal("delayed Put returned successful payload after preparation")
			}
			history := resumer.peer.History(key)
			if len(history) != 1 || !bytes.Equal(history[0].Body, resumeExpectedFence(t, op)) {
				t.Fatal("late payload survived permanent fence")
			}
		})
	}
}

func TestBudgetedResumeKnownPublishedCommitIsRequired(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "publication-commit", resumeMaximum())
	if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: "COMMIT", Slot: "published", OperationLabel: "resume", Occurrence: 1, Err: io.EOF, CommitMode: resumeFixtureTestPersistThenLose}); err != nil {
		t.Fatal(err)
	}
	result, err := g.store.ResumeErasure(g.ResumeContext("resume"), op.Ref(), a)
	resumeZeroResult(t, result, err)
	if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
		t.Fatal("unknown published commit", err)
	}
	before := len(g.peer.Events())
	kms := g.peer.KMSCount(g.name)
	read, found, err := g.store.ReadErasure(g.Context("read-known-state"), op.Ref())
	if err != nil || !found || read.State() != artifact.ErasureState(5) {
		t.Fatal("known snapshot did not reconcile durable published closure", err)
	}
	if len(g.peer.Events()) != before || g.peer.KMSCount(g.name) != kms {
		t.Fatal("read replayed uncertain publication")
	}
}
func TestBudgetedResumeLaterUnknownReservationKeepsEarlierEffects(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "later-unknown", resumeMaximum())
	if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: "COMMIT", Mutation: "attempt_insert", OperationLabel: "resume", Occurrence: 4, Err: io.EOF, CommitMode: resumeFixtureTestPersistThenLose}); err != nil {
		t.Fatal(err)
	}
	before := len(g.peer.Events())
	result, err := g.store.ResumeErasure(g.ResumeContext("resume"), op.Ref(), a)
	resumeZeroResult(t, result, err)
	if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
		t.Fatal(err)
	}
	effects := g.peer.Events()[before:]
	if len(effects) != 3 {
		t.Fatal("wrong attribution of effects preceding fourth reservation", len(effects))
	}
	snapshot := g.sql.Snapshot()
	uncertain := ""
	for _, e := range snapshot.Events {
		if e.StatementID == "attempt_insert" && e.Graph == g.name && e.OperationLabel == "resume" && !resumeCommitted(snapshot.Events, e.Graph, e.OperationLabel, e.TransactionID) {
			uncertain = e.Arguments[10].(string)
		}
	}
	if uncertain == "" {
		t.Fatal("uncertain durable reservation missing")
	}
	for _, e := range effects {
		if e.Attempt == uncertain {
			t.Fatal("unknown reservation dispatched")
		}
	}
}
func TestBudgetedResumeEveryAllowanceDimensionHasNoRefund(t *testing.T) {
	for i, dimension := range resumeDimensions {
		t.Run(dimension, func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			maximum := resumeBudgetVector(resumeMaximum())
			maximum[i] = 0
			if i == 0 {
				maximum[0] = 1
				maximum[1] = 1
			}
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "dimension-"+dimension, resumeBudgetFrom(maximum))
			result, err := g.store.ResumeErasure(g.ResumeContext("bounded-resume"), op.Ref(), a)
			if !errors.Is(err, artifact.ErrErasureAllowanceExhausted) || result.State() != artifact.ErasureState(2) {
				t.Fatal("known dimension exhaustion", dimension, err, result.State())
			}
			if _, ok := result.Attestation(); ok {
				t.Fatal("exhaustion certified")
			}
			row := g.sql.Snapshot().Rows[resumeAllowances][0]
			if resumeFixtureSQLInt(row, "spent_"+dimension) > int64(maximum[i]) {
				t.Fatal("ceiling exceeded")
			}
			before := make([]int64, 11)
			for j, d := range resumeDimensions {
				before[j] = resumeFixtureSQLInt(row, "spent_"+d)
			}
			if _, _, err := g.store.ReadErasure(g.Context("read"), op.Ref()); err != nil {
				t.Fatal(err)
			}
			freshRow := g.sql.Snapshot().Rows[resumeAllowances][0]
			for j, d := range resumeDimensions {
				if resumeFixtureSQLInt(freshRow, "spent_"+d) != before[j] {
					t.Fatal("read refunded spending")
				}
			}
		})
	}
}
func TestBudgetedResumeOwnedResponseFaultsCannotCertify(t *testing.T) {
	cases := []struct {
		name, method, key string
		status            int
		body              []byte
		headers           http.Header
		lose              bool
	}{
		{"denied current", "GET", "artifact", 403, []byte("<Error><Code>AccessDenied</Code></Error>"), nil, false},
		{"conflict current", "GET", "artifact", 409, []byte("<Error><Code>Conflict</Code></Error>"), nil, false},
		{"partial body", "GET", "artifact", 206, []byte("part"), nil, false},
		{"bad current checksum", "GET", "artifact", 0, nil, http.Header{"X-Amz-Checksum-Sha256": []string{"invalid"}}, false},
		{"null current version", "GET", "artifact", 0, nil, http.Header{"X-Amz-Version-Id": []string{"null"}}, false},
		{"duplicate current version", "GET", "artifact", 0, nil, http.Header{"X-Amz-Version-Id": []string{"one", "two"}}, false},
		{"malformed current fence", "GET", "artifact", 0, []byte("OTAF0001not-canonical"), http.Header{"X-Amz-Checksum-Sha256": nil, "X-Amz-Checksum-Type": nil}, false},
		{"unsupported content encoding", "GET", "artifact", 0, nil, http.Header{"Content-Encoding": []string{"gzip"}}, false},
		{"lost current reply", "GET", "artifact", 0, nil, nil, true},
		{"malformed list XML", "GET", "list", 0, []byte("<ListVersionsResult>"), nil, false},
		{"wrong list key", "GET", "list", 0, []byte("<ListVersionsResult><Name>synthetic-resume</Name><Prefix>wrong</Prefix><MaxKeys>2</MaxKeys><IsTruncated>false</IsTruncated></ListVersionsResult>"), nil, false},
		{"lost proof create reply", "PUT", "proof", 0, nil, nil, true},
		{"proof body mismatch", "GET", "proof", 200, []byte("wrong-proof"), http.Header{"X-Amz-Version-Id": []string{"proof-version"}, "X-Amz-Checksum-Sha256": nil, "X-Amz-Checksum-Type": nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), tc.name, resumeMaximum())
			key := g.Key().Key()
			if tc.key == "proof" {
				key = resumeAttestationKey(g.resumeJournalGraph)
			}
			fault := resumePeerFault{Graph: g.name, Method: tc.method, Key: key, Occurrence: 1, Status: tc.status, Body: tc.body, Headers: tc.headers, Lose: tc.lose}
			if tc.key == "list" {
				fault.ListOnly = true
			}
			g.peer.Fault(fault)
			before := len(g.peer.Events())
			result, err := g.store.ResumeErasure(g.ResumeContext("faulted-resume"), op.Ref(), a)
			if err == nil || result.State() == artifact.ErasureState(5) {
				t.Fatal("fault certified", err)
			}
			if _, ok := result.Attestation(); ok {
				t.Fatal("fault carried attestation")
			}
			if errors.Is(err, artifact.ErrErasureUnknownOutcome) {
				resumeZeroResult(t, result, err)
			}
			if tc.name == "malformed current fence" && result.State() != artifact.ErasureState(4) {
				t.Fatal("malformed current fence was not blocked", err)
			}
			for _, e := range g.peer.Events()[before:] {
				if e.Method == "DELETE" && e.Key == key && tc.name == "malformed current fence" {
					t.Fatal("malformed current fence was deleted")
				}
			}
			snapshot := g.sql.Snapshot()
			for _, row := range snapshot.Rows[resumeEvidence] {
				if row["slot"] == "published" {
					t.Fatal("fault published evidence")
				}
			}
			expectedCode := ""
			if tc.lose {
				expectedCode = "unavailable"
			}
			switch tc.name {
			case "partial body", "bad current checksum", "null current version", "duplicate current version", "unsupported content encoding", "malformed list XML", "wrong list key":
				expectedCode = "malformed"
			}
			if expectedCode != "" {
				resumeZeroResult(t, result, err)
				if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
					t.Fatal("wire uncertainty classification", err)
				}
				effects := g.peer.Events()[before:]
				if len(effects) == 0 {
					t.Fatal("fault did not reach owned backend")
				}
				failed := effects[len(effects)-1].Attempt
				var response, unknown resumeFixtureRow
				for _, row := range snapshot.Rows[resumeEvidence] {
					if row["attempt_identity"] == failed {
						if row["kind"] == "response" {
							response = row
						}
						if row["kind"] == "unknown" {
							unknown = row
						}
					}
				}
				if response == nil || unknown == nil {
					t.Fatal("owner response failure was not atomic uncertainty")
				}
				record := resumeDecodeObject(t, resumeEvidenceInner(t, response["canonical_evidence"].([]byte)))
				if string(record["code"]) != "\""+expectedCode+"\"" || string(record["entries"]) != "[]" || string(record["record_hex"]) != "\"\"" {
					t.Fatal("uncertain response retained usable partial content")
				}
				first, second := uint64(0), uint64(0)
				for _, e := range snapshot.Events {
					if e.StatementID == "evidence_insert" && len(e.Arguments) == 14 {
						if e.Arguments[8] == response["evidence_identity"] {
							first = e.TransactionID
						}
						if e.Arguments[8] == unknown["evidence_identity"] {
							second = e.TransactionID
						}
					}
				}
				if first == 0 || first != second || !resumeCommitted(snapshot.Events, g.name, "faulted-resume", first) {
					t.Fatal("new unknown and response did not share a known commit")
				}
			}
		})
	}
}
func TestBudgetedResumeConstructorScopesAndOldModes(t *testing.T) {
	for _, mode := range []string{"zero witness", "same DB other index", "same authority other DB", "nil backend", "nil keys", "nil clock", "zero policy"} {
		t.Run(mode, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			index, policy := g.index, g.policy
			deps := BudgetedEnvelopeDependencies{Backend: g.backend, Keys: g.keys, Clock: g.clock, IndexAuthority: g.witness}
			var err error
			switch mode {
			case "zero witness":
				deps.IndexAuthority = VerifiedBudgetedErasureIndex{}
			case "same DB other index":
				index, err = NewArtifactIndex(g.db)
			case "same authority other DB":
				index, err = NewArtifactIndex(g.sql.OpenDB(t, "different-handle"))
			case "nil backend":
				deps.Backend = nil
			case "nil keys":
				var nilKeys *awskms.Provider
				deps.Keys = nilKeys
			case "nil clock":
				var nilClock *resumeClock
				deps.Clock = nilClock
			case "zero policy":
				policy = artifact.ProtectedErasurePolicy{}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, wire := len(g.sql.Snapshot().Events), len(g.peer.Events())
			store, err := NewIndexedBudgetedEnvelopeStore(index, deps, policy)
			if err == nil || store != nil || before != len(g.sql.Snapshot().Events) || wire != len(g.peer.Events()) {
				t.Fatal("local construction guard")
			}
		})
	}
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "old-mode", resumeMaximum())
	plain, err := artifact.NewEnvelopeStore(g.policy.Prefix(), g.backend, g.keys)
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewIndexedArtifactStore(g.index, plain)
	if err != nil {
		t.Fatal(err)
	}
	before := len(g.peer.Events())
	result, err := old.ResumeErasure(g.Context("old-mode"), op.Ref(), a)
	resumeZeroResult(t, result, err)
	if !errors.Is(err, artifact.ErrErasureJournalRequired) {
		t.Fatal("old indexed mode acquired Resume", err)
	}
	result, found, err := old.ReadErasure(g.Context("old-read"), op.Ref())
	resumeZeroResult(t, result, err)
	if found || !errors.Is(err, artifact.ErrErasureJournalRequired) {
		t.Fatal("old indexed Read acquired mode")
	}
	deleted, err := g.backend.Delete(context.Background(), g.Key().Key(), "version:synthetic")
	if deleted || !errors.Is(err, artifact.ErrErasureBackendUnsupported) || len(g.peer.Events()) != before {
		t.Fatal("generic Delete dispatched")
	}
}
func TestBudgetedResumeInvalidContextAndClockNeverDispatch(t *testing.T) {
	for _, mode := range []string{"cancelled", "nil context", "expired", "not yet valid", "submillisecond", "backward", "wrong scope"} {
		t.Run(mode, func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			at := g.clock.Value()
			a, _, _ := resumeAllowance(t, g.policy, op, at, "clock", resumeMaximum())
			ctx := g.ResumeContext("clock-guard")
			ref := op.Ref()
			switch mode {
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "nil context":
				ctx = nil
			case "expired":
				g.clock.Set(a.NotAfter())
			case "not yet valid":
				a, _, _ = resumeAllowance(t, g.policy, op, at.Add(time.Second), "future", resumeMaximum())
			case "submillisecond":
				g.clock.Set(at.Add(time.Nanosecond))
			case "backward":
				g.clock.Set(at.Add(-time.Millisecond))
			case "wrong scope":
				scope, err := audit.NewReviewScope("other-tenant", g.scope.RepositoryID(), g.scope.ReviewRunID())
				if err != nil {
					t.Fatal(err)
				}
				ref, err = artifact.NewErasureOperationRef(scope, op.NamespaceIdentity(), op.Identity())
				if err != nil {
					t.Fatal(err)
				}
			}
			before := len(g.peer.Events())
			result, err := g.store.ResumeErasure(ctx, ref, a)
			if err == nil || result.State() == artifact.ErasureState(5) || len(g.peer.Events()) != before {
				t.Fatal("clock/context guard dispatched", mode, err)
			}
			if _, ok := result.Attestation(); ok {
				t.Fatal("guard certified")
			}
		})
	}
}
func TestBudgetedResumeCorruptedProductWrittenProofCannotBeRead(t *testing.T) {
	for _, slot := range []string{"fence", "candidate", "published"} {
		t.Run(slot, func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "corrupt-proof", resumeMaximum())
			result, err := g.store.ResumeErasure(g.ResumeContext("complete"), op.Ref(), a)
			assertResumeCertified(t, g, op, result, err)
			var row resumeFixtureRow
			for _, r := range g.sql.Snapshot().Rows[resumeEvidence] {
				if r["slot"] == slot {
					row = r
				}
			}
			if row == nil {
				t.Fatal("product did not insert proof row")
			}
			pk := resumeFixtureTuple(row, []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "slot"})
			if err := g.sql.CorruptExistingRow(resumeEvidence, pk, "canonical_evidence", []byte("corrupted full dependency preimage")); err != nil {
				t.Fatal(err)
			}
			before := len(g.peer.Events())
			read, found, err := g.store.ReadErasure(g.Context("corrupt-read"), op.Ref())
			resumeZeroResult(t, read, err)
			if found || len(g.peer.Events()) != before {
				t.Fatal("corrupt immutable read escaped")
			}
		})
	}
}

var _ artifact.BudgetedErasureStore = (*IndexedArtifactStore)(nil)
var _ artifact.BudgetedErasureStore = (*artifact.EnvelopeStore)(nil)

func TestBudgetedResumeEscapedHistoryUsesActualPageSelection(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("the normal suite covers the deterministic 241-version stress boundary")
	}
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	for i := 0; i < 241; i++ {
		g.peer.AddOpaqueHistory(t, g.Key().Key(), strings.Repeat("\\", 496)+fmt.Sprintf("%08d", i), false, []byte("synthetic historical ciphertext"))
	}
	g.peer.AddHistory(t, g.Key().Key(), true, nil)
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "escaped-history", resumeMaximum())
	sawList := false
	type retainedListUnknown struct {
		allowance        artifact.ResumeAllowance
		usage            artifact.AllowanceUsage
		attemptIdentity  string
		unknownIdentity  string
		unknownCanonical []byte
	}
	var retainedUnknowns []retainedListUnknown
	for invocation := 0; invocation < 64; invocation++ {
		label := fmt.Sprintf("escaped-resume-%d", invocation)
		if invocation > 0 {
			a, _, _ = resumeAllowance(t, g.policy, op, g.clock.Value(), label, resumeMaximum())
		}
		before := len(g.peer.Events())
		invocationStarted := time.Now()
		invocationContext := g.ResumeContext(label)
		result, err := g.store.ResumeErasure(invocationContext, op.Ref(), a)
		invocationElapsed := time.Since(invocationStarted)
		invocationObserved := g.clock.Value()
		snapshot := g.sql.Snapshot()
		events := g.peer.Events()[before:]
		overflow := false
		var invocationUnknowns []resumeListResponseOracle
		for _, event := range events {
			q, _ := url.ParseQuery(event.Query)
			if !q.Has("versions") {
				continue
			}
			sawList = true
			oracle := resumeAssertVersionListResponseOracle(t, g, op, snapshot, event, a, label, invocationObserved)
			switch oracle.Response.Code {
			case artifact.AttemptResponsePresent:
				// The shared oracle already decoded the independently captured wire page and
				// compared it with the committed canonical Present response at the stored
				// observation time.
			case artifact.AttemptResponseMalformed:
				if !oracle.RawOverflow && !oracle.CanonicalOverflow {
					t.Fatal("malformed list response was not a supported overflow refusal")
				}
				overflow = true
				resumeZeroResult(t, result, err)
				if !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
					t.Fatal("owner failed atomic list-refusal handling", err)
				}
				progress, found, readErr := g.journal.ReadErasureProgress(g.Context("refused-list-spend"), op.Ref(), oracle.Request.AllowanceIdentity())
				if readErr != nil || !found {
					t.Fatal("refused list usage", readErr)
				}
				usage := resumeSingleUsage(t, progress, a)
				resumeAssertAllowanceUsageMatchesAttempts(t, g, snapshot, a, usage)
				if oracle.RawOverflow {
					t.Log("owned body-cap refusal; intended response is not proof of full client receipt")
				} else {
					t.Log("intended raw body fits; canonical response exceeds262144 bytes")
				}
				for _, later := range events {
					if later.Sequence > event.Sequence {
						t.Fatal("owner dispatched after refused list")
					}
				}
			case artifact.AttemptResponseUnavailable:
				invocationUnknowns = append(invocationUnknowns, oracle)
			default:
				t.Fatal("unsupported durable version-list response", oracle.Response.Code)
			}
		}
		resumeAssertDeletesUseCommittedUsableObservations(t, g, op, snapshot, events)
		if overflow {
			return
		}
		if err == nil && result.State() == artifact.ErasureState(5) {
			assertResumeCertified(t, g, op, result, err)
			if !sawList {
				t.Fatal("owner avoided required version inventory")
			}
			if len(retainedUnknowns) != 0 && !result.HasUnknownHistory() {
				t.Fatal("certified recovery dropped earlier unknown history")
			}
			certifiedSnapshot := g.sql.Snapshot()
			for _, retained := range retainedUnknowns {
				progress, found, readErr := g.journal.ReadErasureProgress(g.Context("retained-unknown-usage"), op.Ref(), retained.allowance.Identity())
				if readErr != nil || !found {
					t.Fatal("retained unknown allowance usage read", readErr)
				}
				if usage := resumeSingleUsage(t, progress, retained.allowance); usage != retained.usage {
					t.Fatal("later recovery changed original unknown allowance spending", usage, retained.usage)
				}
				row := resumeEvidenceRowByIdentity(certifiedSnapshot, retained.unknownIdentity)
				if row == nil || !bytes.Equal(row["canonical_evidence"].([]byte), retained.unknownCanonical) {
					t.Fatal("later recovery changed original unknown canonical evidence")
				}
				if count := resumePeerAttemptDispatches(g.peer.Events(), retained.attemptIdentity); count != 1 {
					t.Fatal("unknown version-list attempt was replayed", count)
				}
			}
			return
		}
		unknownBoundary := errors.Is(err, artifact.ErrErasureUnknownOutcome)
		if unknownBoundary {
			resumeZeroResult(t, result, err)
			if invocationElapsed < 90*time.Second || invocationContext.Err() != nil || invocationObserved.Before(a.NotBefore()) || !invocationObserved.Before(a.NotAfter()) || !g.policy.AllowsAt(invocationObserved) {
				t.Fatal("unknown list response did not reach the explicit invocation boundary", invocationElapsed, invocationContext.Err())
			}
			if len(invocationUnknowns) != 1 {
				t.Fatal("unknown boundary did not retain exactly one failed version-list response", len(invocationUnknowns))
			}
			oracle := invocationUnknowns[0]
			progress, found, readErr := g.journal.ReadErasureProgress(g.Context("unknown-list-spend"), op.Ref(), oracle.Request.AllowanceIdentity())
			if readErr != nil || !found {
				t.Fatal("unknown list usage", readErr)
			}
			usage := resumeSingleUsage(t, progress, a)
			resumeAssertAllowanceUsageMatchesAttempts(t, g, snapshot, a, usage)
			if count := resumePeerAttemptDispatches(g.peer.Events(), oracle.Attempt.Identity()); count != 1 {
				t.Fatal("unknown version-list attempt was replayed", count)
			}
			for _, later := range events {
				if later.Sequence > oracle.Event.Sequence {
					t.Fatal("owner dispatched after failed version-list response")
				}
			}
			retainedUnknowns = append(retainedUnknowns, retainedListUnknown{allowance: a, usage: usage, attemptIdentity: oracle.Attempt.Identity(), unknownIdentity: oracle.UnknownRow["evidence_identity"].(string), unknownCanonical: append([]byte(nil), oracle.UnknownRow["canonical_evidence"].([]byte)...)})
			t.Logf("explicit invocation %d reached unchanged 90-second limit with committed list uncertainty and active allowance/policy", invocation)
			continue
		}
		invocationExpired := errors.Is(err, artifact.ErrErasureAllowanceExpired) &&
			invocationElapsed >= 90*time.Second && invocationContext.Err() == nil &&
			invocationObserved.Before(a.NotAfter()) && g.policy.AllowsAt(invocationObserved)
		if (!errors.Is(err, artifact.ErrErasureAllowanceExhausted) && !invocationExpired) || result.State() != artifact.ErasureState(2) {
			t.Fatal("encodable history failed bounded convergence", err, result.State(), invocationElapsed)
		}
		if invocationExpired {
			t.Logf("explicit invocation %d reached unchanged 90-second limit with active allowance/policy; retained Pending progress", invocation)
		}
	}
	t.Fatal("encodable selected pages did not converge within finite invocations")
}

func TestBudgetedResumeExpectedOwnerAndLegacyObjectsBlock(t *testing.T) {
	for _, mode := range []string{"owner", "legacy intent", "legacy receipt"} {
		t.Run(mode, func(t *testing.T) {
			g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
			_, op, _ := g.Prepared()
			owner := resumeOwner
			if mode == "owner" {
				owner = "999999999999"
			}
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), mode, resumeMaximum(), owner)
			secret := []byte("synthetic legacy body never belongs in SQL")
			if mode != "owner" {
				suffix := ".intent"
				if mode == "legacy receipt" {
					suffix = ".receipt"
				}
				key := resumePrefix + "/deletions/" + g.scope.Identity() + "/" + g.value.Identity() + suffix
				g.peer.Fault(resumePeerFault{Graph: g.name, Method: "GET", Key: key, Occurrence: 1, Status: 200, Body: secret, Headers: http.Header{"X-Amz-Version-Id": []string{"legacy-version"}}})
			}
			result, err := g.store.ResumeErasure(g.ResumeContext("blocked"), op.Ref(), a)
			if err == nil || result.State() != artifact.ErasureState(4) {
				t.Fatal("known blocked boundary", err)
			}
			if _, ok := result.Attestation(); ok {
				t.Fatal("blocked boundary certified")
			}
			for _, rows := range g.sql.Snapshot().Rows {
				for _, row := range rows {
					for _, value := range row {
						if raw, ok := value.([]byte); ok && bytes.Contains(raw, secret) {
							t.Fatal("legacy object body retained in SQL")
						}
					}
				}
			}
			before := len(g.peer.Events())
			authorization, err := artifact.NewDeletionAuthorization(g.scope, g.value.Identity(), strings.Repeat("5", 64), "operator", strings.Repeat("9", 64), artifact.DeletionTenantErasure, g.clock.Value().Add(-time.Second), g.clock.Value().Add(time.Minute))
			if err != nil || authorization.Validate() != nil || !authorization.Allows(g.value, g.clock.Value()) {
				t.Fatal("valid legacy authorization control", err)
			}
			receipt, err := g.store.Delete(g.Context("legacy-delete"), authorization, g.clock.Value())
			if !errors.Is(err, artifact.ErrErasureAuthorizationV2Required) || receipt.Identity() != "" || len(g.peer.Events()) != before {
				t.Fatal("new-mode Delete bypass", err)
			}
		})
	}
}

func resumeAssertIndependentAttestation(t *testing.T, g *budgetedResumeGraph, op artifact.ErasureOperation, a artifact.ErasureAttestationV2, policy artifact.ProtectedErasurePolicy, body []byte) {
	t.Helper()
	p, found, err := g.journal.ReadErasureProgress(g.Context("independent-proof-closure"), op.Ref(), "")
	if err != nil || !found {
		t.Fatal(err)
	}
	fence, ok := p.Fence()
	if !ok {
		t.Fatal("missing fence")
	}
	history := g.peer.History(g.Key().Key())
	if len(history) != 1 {
		t.Fatal("fence history")
	}
	versionFields := map[string]any{"contract": "open-trestle/artifact-object-version", "schema_version": 1, "namespace_identity": op.NamespaceIdentity(), "key": g.Key().Key(), "kind": "data", "version_id": history[0].ID}
	resumeOrdered(t, versionFields, "contract schema_version identity namespace_identity key kind version_id", "open-trestle/artifact-object-version/v1\x00")
	version, err := artifact.ParseObjectVersion(fence.RecordBytes())
	if err != nil || version.Identity() != versionFields["identity"] || version.Key() != g.Key().Key() || version.VersionID() != history[0].ID {
		t.Fatal("fence record, request and accepted key equality", err)
	}
	var verification artifact.ErasureVerification
	for _, e := range p.Evidence() {
		if e.Kind() == "verification" {
			v, err := artifact.ParseErasureVerification(e.RecordBytes(), op.Ref())
			if err != nil {
				t.Fatal(err)
			}
			if v.Identity() == a.VerificationIdentity() {
				verification = v
			}
		}
	}
	if verification.Identity() == "" {
		t.Fatal("full selected verification preimage missing")
	}
	evidence := func(id string) artifact.ErasureEvidence {
		for _, e := range p.Evidence() {
			if e.Identity() == id {
				return e
			}
		}
		t.Fatal("missing evidence preimage")
		return artifact.ErasureEvidence{}
	}
	attempt := func(id string) artifact.ErasureAttempt {
		for _, a := range p.Attempts() {
			if a.Identity() == id {
				return a
			}
		}
		t.Fatal("missing request/attempt preimage")
		return artifact.ErasureAttempt{}
	}
	lists := verification.ListResponseIdentities()
	if len(lists) != 1 {
		t.Fatal("terminal list cardinality")
	}
	list, current := evidence(lists[0]), evidence(verification.CurrentResponseIdentity())
	listAttempt, currentAttempt := attempt(list.AttemptIdentity()), attempt(current.AttemptIdentity())
	lr, cr := listAttempt.Request(), currentAttempt.Request()
	if lr.Kind() != artifact.AttemptVersionList || lr.Key() != g.Key().Key() || lr.PageLimit() != 2 || lr.KeyMarker() != "" || lr.VersionIDMarker() != "" || cr.Kind() != artifact.AttemptCurrentRead || cr.Key() != g.Key().Key() || listAttempt.Identity() == currentAttempt.Identity() || listAttempt.ReservedAt().Before(fence.ObservedAt()) || currentAttempt.ReservedAt().Before(list.ObservedAt()) {
		t.Fatal("fresh terminal request inputs")
	}
	l, err := artifact.ParseAttemptResponseEvidence(list, listAttempt)
	if err != nil || l.Code != artifact.AttemptResponsePresent || l.Page.Truncated || l.Page.Next != (artifact.VersionCursor{}) || len(l.Page.Entries) != 1 || !l.Page.Entries[0].IsLatest || l.Page.Entries[0].Version.Kind() != artifact.ObjectVersionData || l.Page.Entries[0].Version.VersionID() != history[0].ID || l.Page.Entries[0].Version.Key() != g.Key().Key() {
		t.Fatal("terminal singleton fence observation", err)
	}
	c, err := artifact.ParseAttemptResponseEvidence(current, currentAttempt)
	if err != nil || c.Code != artifact.AttemptResponsePresent || c.Version.VersionID() != history[0].ID || c.Version.Key() != g.Key().Key() || !bytes.Equal(c.CanonicalRecord, resumeExpectedFence(t, op)) {
		t.Fatal("separate whole-current fence observation", err)
	}
	fenceFields := resumeDecodeObject(t, resumeExpectedFence(t, op)[8:])
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-attestation", "schema_version": 2, "namespace_identity": op.NamespaceIdentity(), "scope_identity": op.Scope().Identity(), "artifact_identity": op.ArtifactIdentity(), "payload_digest": g.value.PayloadDigest(), "admission_identity": op.AdmissionIdentity(), "operation_identity": op.Identity(), "original_authorization_identity": op.OriginalAuthorizationIdentity(), "authorization_document_digest": op.AuthorizationDocumentDigest(), "erasure_protocol": "same-key-fence-v2", "policy_identity": op.PolicyIdentity(), "protected_policy_identity": op.ProtectedPolicyIdentity(), "resume_policy_identity": policy.Identity(), "configuration_evidence_identity": policy.ConfigurationEvidenceIdentity(), "fence_identity": fenceFields["identity"], "fence_version_identity": versionFields["identity"], "verification_identity": verification.Identity(), "prepared_at_milliseconds": op.PreparedAt().UnixMilli(), "verified_at_milliseconds": verification.VerifiedAt().UnixMilli(), "completed_at_milliseconds": verification.CompletedAt().UnixMilli(), "proof_scope": "all_versions_at_exact_key", "remaining_data_versions": 1, "remaining_delete_markers": 0, "remaining_record": "content_free_fence", "legacy_receipt_identity": ""}
	expected := resumeOrdered(t, fields, "contract schema_version identity namespace_identity scope_identity artifact_identity payload_digest admission_identity operation_identity original_authorization_identity authorization_document_digest erasure_protocol policy_identity protected_policy_identity resume_policy_identity configuration_evidence_identity fence_identity fence_version_identity verification_identity prepared_at_milliseconds verified_at_milliseconds completed_at_milliseconds proof_scope remaining_data_versions remaining_delete_markers remaining_record legacy_receipt_identity", "open-trestle/artifact-erasure-attestation/v2\x00")
	if !bytes.Equal(body, expected) || a.Identity() != fields["identity"].(string) || a.VerifiedAt() != verification.VerifiedAt() || a.CompletedAt() != verification.CompletedAt() {
		t.Fatal("independent canonical attestation bytes or original times")
	}
}

func (g *budgetedResumeGraph) ResumeContext(label string) context.Context {
	g.invocations[label] = true
	g.peer.mu.Lock()
	authority := g.peer.graphs[g.name]
	if authority.reservedInvocations == nil {
		authority.reservedInvocations = map[string]bool{}
	}
	authority.reservedInvocations[label] = true
	g.peer.mu.Unlock()
	return g.Context(label)
}
func (g *budgetedResumeGraph) assertInvocationBudgets(t *testing.T) {
	t.Helper()
	snapshot := g.sql.Snapshot()
	ceilings := []uint64{256, 160, 128, 64, 16, 128, 64, 4096, 64 << 20, 8 << 20, 128 << 10}
	for label := range g.invocations {
		totals := make([]uint64, 11)
		fenceCreates := 0
		seen := map[string]bool{}
		for _, event := range snapshot.Events {
			if event.StatementID != "attempt_insert" || event.Graph != g.name || event.OperationLabel != label {
				continue
			}
			persisted := false
			for _, commit := range snapshot.Events {
				if commit.TransactionID == event.TransactionID && commit.StatementID == "COMMIT" && commit.Persisted {
					persisted = true
				}
			}
			if !persisted {
				continue
			}
			request, err := artifact.ParseAttemptRequest(event.Arguments[12].([]byte), g.scope)
			if err != nil {
				t.Error("invalid committed request", err)
				continue
			}
			if seen[request.ReservationIdentity()] {
				continue
			}
			seen[request.ReservationIdentity()] = true
			price := resumeBudgetVector(resumeCost(request))
			for i, n := range price {
				totals[i] += n
			}
			if request.Kind() == artifact.AttemptFenceCreate {
				fenceCreates++
			}
		}
		for i, n := range totals {
			if n > ceilings[i] {
				t.Errorf("invocation %s exceeded %s: %d > %d", label, resumeDimensions[i], n, ceilings[i])
			}
		}
		if fenceCreates > 8 {
			t.Errorf("invocation %s exceeded eight fence creates", label)
		}
	}
}

func TestBudgetedResumeExpiryAfterKnownReservationSpendsWithoutDispatch(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if now.Before(g.clock.Value()) {
		now = g.clock.Value()
	}
	g.clock.Set(now)
	_, _, raw := resumeAllowance(t, g.policy, op, now, "pre-dispatch-expiry", resumeMaximum())
	record := resumeDecodeObject(t, raw)
	fields := map[string]any{}
	for k, v := range record {
		fields[k] = v
	}
	end := now.Add(30 * time.Second)
	fields["not_after_milliseconds"] = end.UnixMilli()
	changed := resumeOrdered(t, fields, "contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest recovery_policy_identity protected_policy_identity principal_identity issuance_identity expected_bucket_owner not_before_milliseconds not_after_milliseconds maximum", "open-trestle/artifact-erasure-resume-allowance/v1\x00")
	allowance, err := artifact.LoadResumeAllowance(context.Background(), erasureProtectedFile(t, changed), g.policy, g.scope)
	if err != nil {
		t.Fatal(err)
	}
	g.clock.mu.Lock()
	g.clock.afterKnownReservation = end
	g.clock.mu.Unlock()
	before := len(g.peer.Events())
	result, err := g.store.ResumeErasure(g.ResumeContext("late-expiry"), op.Ref(), allowance)
	if !errors.Is(err, artifact.ErrErasureAllowanceExpired) || result.State() != artifact.ErasureState(2) || len(g.peer.Events()) != before {
		t.Fatal("expired known reservation dispatched or returned wrong outcome", err, result.State())
	}
	if _, ok := result.Attestation(); ok {
		t.Fatal("expired invocation certified")
	}
	progress, found, err := g.journal.ReadErasureProgress(g.Context("expired-usage"), op.Ref(), allowance.Identity())
	if err != nil || !found || len(progress.AllowanceUsages()) != 1 || progress.AllowanceUsages()[0].Spent.Requests != 1 {
		t.Fatal("expired reservation refunded or disappeared", err)
	}
}

func TestBudgetedResumeCancellationAfterFenceWriteReconcilesWithoutReplay(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "cancelled-write", resumeMaximum())
	entered, release := make(chan struct{}), make(chan struct{})
	g.peer.Fault(resumePeerFault{Graph: g.name, Method: "PUT", Key: g.Key().Key(), Occurrence: 1, After: true, Entered: entered, Release: release})
	workers := newResumeWorkers(t)
	ctx, cancel := context.WithCancel(g.ResumeContext("cancelled-resume"))
	defer cancel()
	type reply struct {
		result artifact.ErasureResult
		err    error
	}
	done := make(chan reply, 1)
	workers.Start(ctx, func(owned context.Context) {
		result, err := g.store.ResumeErasure(owned, op.Ref(), a)
		done <- reply{result, err}
	})
	resumeWait(t, entered)
	cancel()
	timer := time.NewTimer(6 * time.Second)
	var stopped reply
	select {
	case stopped = <-done:
	case <-timer.C:
		t.Fatal("cancelled owner did not return")
	}
	timer.Stop()
	resumeZeroResult(t, stopped.result, stopped.err)
	if !errors.Is(stopped.err, artifact.ErrErasureUnknownOutcome) {
		t.Fatal("possible transmission cancellation", stopped.err)
	}
	close(release)
	events := g.peer.Events()
	writes := 0
	for _, e := range events {
		if e.Method == "PUT" && e.Key == g.Key().Key() && e.Invocation == "cancelled-resume" {
			writes++
		}
	}
	if writes != 1 {
		t.Fatal("cancelled create was retried")
	}
	before := len(g.peer.Events())
	read, found, err := g.store.ReadErasure(g.Context("cancelled-read"), op.Ref())
	if err != nil || !found || read.State() == artifact.ErasureState(5) || !read.HasUnknownHistory() || len(g.peer.Events()) != before {
		t.Fatal("uncertain read replayed or certified", err)
	}
	result, err := g.store.ResumeErasure(g.ResumeContext("explicit-reconcile"), op.Ref(), a)
	assertResumeCertified(t, g, op, result, err)
	if !result.HasUnknownHistory() {
		t.Fatal("cancelled transmission history disappeared")
	}
	writes = 0
	for _, e := range g.peer.Events() {
		if e.Method == "PUT" && e.Key == g.Key().Key() && e.Header.Get("X-Amz-Expected-Bucket-Owner") != "" {
			writes++
		}
	}
	if writes != 1 {
		t.Fatal("reconciliation replayed an old fence create")
	}
}
