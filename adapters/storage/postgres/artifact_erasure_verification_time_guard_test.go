package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func resumeVerificationTimeInput(t *testing.T) (*resumeJournalGraph, artifact.ErasureOperation, artifact.ResumeAllowance, artifact.ErasureEvidence) {
	t.Helper()
	g, _, op, allowance, current := resumeJournalFenceInput(t)
	fence, err := artifact.NewFenceObservationEvidence(op, g.Key(), current, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	fence = resumeJournalRecord(t, g, op, fence)
	_, list := resumeJournalList(t, g, op, allowance, "terminal-list", 2, artifact.VersionCursor{})
	_, full := resumeJournalRead(t, g, op, allowance, artifact.AttemptCurrentRead, g.Key(), "terminal-current")
	verification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, full, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.NewVerificationEvidence(verification)
	if err != nil {
		t.Fatal(err)
	}
	return g, op, allowance, verified
}

func TestResumeJournalVerificationRequiresCurrentWindow(t *testing.T) {
	for _, kind := range []string{"allowance_expired", "current_policy_expired", "current_policy_not_active_at_decision"} {
		t.Run(kind, func(t *testing.T) {
			g, op, allowance, verified := resumeVerificationTimeInput(t)
			captured := allowance.NotAfter()
			if kind != "allowance_expired" {
				decision := verified.ObservedAt()
				changes := map[string]any{}
				captured = decision.Add(time.Millisecond)
				if kind == "current_policy_expired" {
					changes["not_after_milliseconds"] = captured.UnixMilli()
				} else {
					changes["not_before_milliseconds"] = decision.Add(time.Millisecond).UnixMilli()
					captured = decision.Add(2 * time.Millisecond)
				}
				policy := resumePolicy(t, g.sql.catalog, g.backend, decision, changes)
				g = newResumeJournalGraph(t, g.sql, g.peer, g.value, policy, captured, "renewed")
			} else {
				g.clock.Set(captured)
			}
			got, inserted, err := g.journal.RecordErasureEvidence(g.Context("expired-new-verification"), op.Ref(), verified)
			if !errors.Is(err, artifact.ErrErasureAllowanceExpired) || inserted || got.Identity() != "" {
				t.Fatalf("new verification outside current windows: inserted=%v identity_present=%v expired_error=%v", inserted, got.Identity() != "", errors.Is(err, artifact.ErrErasureAllowanceExpired))
			}
		})
	}
}

func TestResumeJournalHistoricalVerificationAdoptionAfterExpiry(t *testing.T) {
	g, op, allowance, verified := resumeVerificationTimeInput(t)
	resumeJournalRecord(t, g, op, verified)
	g.clock.Set(allowance.NotAfter())
	got, inserted, err := g.journal.RecordErasureEvidence(g.Context("historical-verification"), op.Ref(), verified)
	if err != nil || inserted || got.Identity() != verified.Identity() {
		t.Fatal("historical verification adoption changed", err)
	}
	progress, found, err := g.journal.ReadErasureProgress(g.Context("historical-progress"), op.Ref(), allowance.Identity())
	if err != nil || !found || progress.Validate() != nil {
		t.Fatal("historical progress expired", err)
	}
}
