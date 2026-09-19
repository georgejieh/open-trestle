package postgres

import (
	"github.com/georgejieh/open-trestle/artifact"
	"testing"
)

func TestBudgetedReadPreparedDoesNotClaimNoHistoricalSpending(t *testing.T) {
	g := newBudgetedResumeGraph(t, newResumeJournalFixture(t))
	_, op, _ := g.Prepared()
	before, found, err := g.store.ReadErasure(g.Context("prepared-view"), op.Ref())
	if err != nil || !found || before.State() != artifact.ErasureStatePrepared {
		t.Fatal("prepared view", err)
	}
	allowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "resolved-before-fence", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-before-fence"), op.Ref(), allowance, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	key, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), resumePrefix+"/deletions/"+g.scope.Identity()+"/"+g.value.Identity()+".intent")
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRead(t, g.resumeJournalGraph, op, allowance, artifact.AttemptIntentRead, key, "resolved-legacy-absence")
	revision, wires, samples := g.sql.Snapshot().Revision, len(g.peer.Events()), g.clock.Samples()
	read, found, err := g.store.ReadErasure(g.Context("bounded-historical-view"), op.Ref())
	if err != nil || !found || read.State() != artifact.ErasureStatePrepared || read.Operation().Identity() != op.Identity() || read.HasUnknownHistory() {
		t.Fatal("bounded historical view", err)
	}
	if _, ok := read.Usage(); ok {
		t.Fatal("unrequested usage claimed")
	}
	if _, ok := read.Attestation(); ok {
		t.Fatal("prepared view certified")
	}
	if g.sql.Snapshot().Revision != revision || len(g.peer.Events()) != wires || g.clock.Samples() != samples {
		t.Fatal("read changed state, sampled time, or dispatched")
	}
	progress, found, err := g.journal.ReadErasureProgress(g.Context("explicit-usage"), op.Ref(), allowance.Identity())
	if err != nil || !found || len(progress.AllowanceUsages()) != 1 {
		t.Fatal("explicit usage", err)
	}
	usage := progress.AllowanceUsages()[0]
	if usage.Spent.Requests != 1 || usage.Spent.Reads != 1 || usage.NextSequence != 2 {
		t.Fatal("resolved historical spending was erased")
	}
}
