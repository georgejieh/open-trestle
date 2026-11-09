package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// refusedStartupFixture seeds the exact nine-task v4 settled within its lease
// as a recorded route refusal, followed by the first suffix events of the
// closed cleanup protocol: up to three dependency skips, then the run failure.
func refusedStartupFixture(t *testing.T, suffix int) (recordedNamesFixture, time.Time) {
	t.Helper()
	var refusedAt time.Time
	f := expiryStartupFixtureAfter(t, func(f *recordedNamesFixture) {
		ctx := context.Background()
		plan := f.fact.Plan()
		refusedAt = f.fact.PreparedEvent().OccurredAt().Add(time.Millisecond)
		shortfall := controlplane.TaskFailureContextShortfall{RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}
		if _, err := f.coordinator.RefusePreparedContextPacket(ctx, plan, f.lease, f.prepared, controlplane.TaskFailureReasonRouteContextInsufficient, shortfall, refusedAt); err != nil {
			t.Fatal(err)
		}
		for i, key := range []string{"candidates", "verification", "readiness"} {
			if i >= suffix {
				break
			}
			_, state, err := f.coordinator.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			task, _ := plan.Task(key)
			event, err := controlplane.NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), controlplane.RunEventTaskSkipped, task, 0, "", "", time.Time{}, "", controlplane.RunFailureDependency, time.Time{}, refusedAt)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.journal.Append(ctx, state.HeadIdentity(), event); err != nil {
				t.Fatal(err)
			}
		}
		if suffix == 4 {
			if _, err := f.coordinator.FailRun(ctx, plan, controlplane.RunFailurePolicy, refusedAt); err != nil {
				t.Fatal(err)
			}
		}
		facts, err := f.journal.InspectHistoricalContextPackets(ctx)
		if err != nil || len(facts) != 1 || facts[0].ExpiryTail() != controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated {
			t.Fatalf("refused fixture facts=%d %v", len(facts), err)
		}
		f.fact = facts[0]
	})
	return f, refusedAt
}

// A crash after the refusal is journaled, after each cleanup suffix event, or
// after the run failed restarts the same way whether the original lease is
// still live or expired: the refused packet is accepted, nothing is appended,
// and a repeated restart observes the same journal.
func TestRefusedV4StartupRecoversEachDurableBoundary(t *testing.T) {
	t.Parallel()
	for suffix := 0; suffix <= 4; suffix++ {
		for _, lease := range []string{"live", "expired"} {
			t.Run(fmt.Sprintf("%d-%s", suffix, lease), func(t *testing.T) {
				f, refusedAt := refusedStartupFixture(t, suffix)
				at := refusedAt.Add(time.Millisecond)
				if lease == "expired" {
					at = f.fact.LeaseEvent().LeaseExpiresAt()
				}
				if !at.Before(f.a.Packet.ExpiresAt()) {
					t.Fatal("fixture packet retention already expired")
				}
				state := f.ownerFixture.statePath
				before := ownerStartupJournalBytes(t, state)
				ledger, err := audit.NewFileLedger(filepath.Join(state, "audit"))
				if err != nil {
					t.Fatal(err)
				}
				defer ledger.Close()
				for restart := 0; restart < 2; restart++ {
					r, owner, err := restartExpiryStartup(t, f, at)
					if err != nil || owner == nil {
						t.Fatalf("restart %d refused a settled refusal: %v", restart, err)
					}
					if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
						t.Fatalf("restart %d proof: %v", restart, err)
					}
					if owner.pendingExpiredPackets != nil {
						t.Fatal("refused packet left pending")
					}
					_, recovered, err := controlplaneCoordinator(t, owner).Resume(context.Background(), f.fact.Plan().Scope())
					task, _ := recovered.Task("context")
					if err != nil || recovered.HeadIdentity() != f.fact.FinalHeadIdentity() || task.FailureReason() != controlplane.TaskFailureReasonRouteContextInsufficient {
						t.Fatalf("restart %d changed the refused run: %v", restart, err)
					}
					if err := r.Close(); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, state)) {
						t.Fatalf("restart %d appended to a refused packet", restart)
					}
				}
			})
		}
	}
}

// The refused packet's evidence is retained and checked exactly as for an
// expiry termination: retention expiry, a missing, corrupt or extra artifact,
// a deletion receipt, or a scope marker keeps startup refused without an append.
func TestRefusedV4StartupRetentionRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"retention-equality", "missing", "corrupt", "orphan", "deletion-receipt", "marker"} {
		t.Run(mode, func(t *testing.T) {
			f, refusedAt := refusedStartupFixture(t, 0)
			at := refusedAt.Add(time.Millisecond)
			state := f.ownerFixture.statePath
			prefix := filepath.Join(state, "artifacts", f.fact.Plan().Scope().Identity()+"-")
			packet := prefix + f.a.Packet.Identity() + ".artifact.json"
			var preserved string
			switch mode {
			case "retention-equality":
				at = f.a.Packet.ExpiresAt()
			case "missing":
				if err := os.Remove(packet); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(packet, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "orphan":
				preserved = prefix + strings.Repeat("a", 64) + ".artifact.json"
			case "deletion-receipt":
				preserved = prefix + f.a.Packet.Identity() + ".artifact-deleted.json"
			case "marker":
				preserved = filepath.Join(state, f.fact.Plan().Scope().Identity()+".scope-intent.json")
			}
			if preserved != "" {
				if err := os.WriteFile(preserved, []byte(mode), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := ownerStartupJournalBytes(t, state)
			r, _, err := restartExpiryStartup(t, f, at)
			if err == nil {
				r.Close()
				t.Fatal("unsafe refused-packet startup accepted")
			}
			if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, state)) {
				t.Fatal("refusal changed journal")
			}
			if preserved != "" {
				if _, err := os.Stat(preserved); err != nil {
					t.Fatal("startup removed marker/receipt/extra")
				}
			}
		})
	}
}
