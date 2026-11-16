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

// While packet retention is live, the refused packet's evidence is checked
// exactly as for an expiry termination: a missing, corrupt or extra artifact,
// a deletion receipt, or a scope marker keeps startup refused without an append.
func TestRefusedV4StartupRetentionRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing", "corrupt", "orphan", "deletion-receipt", "marker"} {
		t.Run(mode, func(t *testing.T) {
			f, refusedAt := refusedStartupFixture(t, 0)
			at := refusedAt.Add(time.Millisecond)
			state := f.ownerFixture.statePath
			prefix := filepath.Join(state, "artifacts", f.fact.Plan().Scope().Identity()+"-")
			packet := prefix + f.a.Packet.Identity() + ".artifact.json"
			var preserved string
			switch mode {
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

// After packet retention lapses, a v4 its journal already settled (a recorded
// route refusal or a lease-expiry termination, with any part of the closed
// cleanup suffix) is proved terminal from the journal and audit alone: startup
// neither reads the expired bytes nor appends, and every later boot reaches
// the same result, also once the expired packet file is gone.
func TestTerminalV4StartupAcceptsAfterRetentionLapse(t *testing.T) {
	t.Parallel()
	for suffix := 0; suffix <= 4; suffix++ {
		for _, mode := range []string{"refused-at-expiry", "refused-later", "refused-packet-removed", "expiry-terminated"} {
			t.Run(fmt.Sprintf("%d-%s", suffix, mode), func(t *testing.T) {
				var f recordedNamesFixture
				if mode == "expiry-terminated" {
					f = expiryTerminatedStartupFixture(t, suffix)
				} else {
					f, _ = refusedStartupFixture(t, suffix)
				}
				at := f.a.Packet.ExpiresAt()
				if mode != "refused-at-expiry" {
					at = at.Add(48 * time.Hour)
				}
				state := f.ownerFixture.statePath
				if mode == "refused-packet-removed" {
					if err := os.Remove(filepath.Join(state, "artifacts", f.fact.Plan().Scope().Identity()+"-"+f.a.Packet.Identity()+".artifact.json")); err != nil {
						t.Fatal(err)
					}
				}
				before := ownerStartupJournalBytes(t, state)
				ledger, err := audit.NewFileLedger(filepath.Join(state, "audit"))
				if err != nil {
					t.Fatal(err)
				}
				defer ledger.Close()
				for restart := 0; restart < 2; restart++ {
					r, owner, err := restartExpiryStartup(t, f, at)
					if err != nil || owner == nil {
						t.Fatalf("restart %d refused a terminal packet after retention: %v", restart, err)
					}
					if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
						t.Fatalf("restart %d proof: %v", restart, err)
					}
					if owner.pendingExpiredPackets != nil {
						t.Fatal("terminal packet left pending")
					}
					if err := r.Close(); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, state)) {
						t.Fatalf("restart %d appended to a terminal packet", restart)
					}
				}
			})
		}
	}
}

// Retention lapse removes only the byte proof. A route effect in the audit, a
// scope marker, or a packet whose journal never settled still refuses startup.
func TestTerminalV4StartupAfterRetentionLapseRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"route", "marker", "unsettled-v4"} {
		t.Run(mode, func(t *testing.T) {
			var f recordedNamesFixture
			if mode == "unsettled-v4" {
				f = expiryStartupFixture(t)
			} else {
				f, _ = refusedStartupFixture(t, 0)
			}
			at := f.a.Packet.ExpiresAt().Add(time.Hour)
			state := f.ownerFixture.statePath
			switch mode {
			case "marker":
				if err := os.WriteFile(filepath.Join(state, f.fact.Plan().Scope().Identity()+".scope-intent.json"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "route":
				ledger, err := audit.NewFileLedger(filepath.Join(state, "audit"))
				if err != nil {
					t.Fatal(err)
				}
				e, err := audit.NewEvent(f.fact.Plan().Scope(), 1, "", audit.EventRouteSelected, strings.Repeat("a", 64), nil, f.fact.LeaseEvent().LeaseExpiresAt())
				if err != nil {
					t.Fatal(err)
				}
				if err := ledger.Append(context.Background(), "", e); err != nil {
					t.Fatal(err)
				}
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := ownerStartupJournalBytes(t, state)
			r, owner, err := restartExpiryStartup(t, f, at)
			if err == nil && owner != nil && mode == "route" {
				ledger, ledgerErr := audit.NewFileLedger(filepath.Join(state, "audit"))
				if ledgerErr != nil {
					t.Fatal(ledgerErr)
				}
				err = verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity())
				ledger.Close()
			}
			if err == nil {
				r.Close()
				t.Fatal("unsafe startup accepted after retention")
			}
			if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, state)) {
				t.Fatal("refusal changed journal")
			}
		})
	}
}

// expiryTerminatedStartupFixture seeds the exact v4 terminated after its lease
// expired, followed by part of the closed cleanup suffix.
func expiryTerminatedStartupFixture(t *testing.T, suffix int) recordedNamesFixture {
	t.Helper()
	return expiryStartupFixtureAfter(t, func(f *recordedNamesFixture) {
		ctx := context.Background()
		plan := f.fact.Plan()
		at := f.fact.LeaseEvent().LeaseExpiresAt()
		if _, err := f.coordinator.TerminatePreparedContextPacket(ctx, plan, f.prepared, at); err != nil {
			t.Fatal(err)
		}
		appendCleanupSuffix(t, f, suffix, at)
		facts, err := f.journal.InspectHistoricalContextPackets(ctx)
		if err != nil || len(facts) != 1 || facts[0].ExpiryTail() != controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated {
			t.Fatalf("terminated fixture facts=%d %v", len(facts), err)
		}
		f.fact = facts[0]
	})
}

// appendCleanupSuffix appends up to three dependency skips, then the run failure.
func appendCleanupSuffix(t *testing.T, f *recordedNamesFixture, suffix int, at time.Time) {
	t.Helper()
	ctx := context.Background()
	plan := f.fact.Plan()
	for i, key := range []string{"candidates", "verification", "readiness"} {
		if i >= suffix {
			break
		}
		_, state, err := f.coordinator.Resume(ctx, plan.Scope())
		if err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task(key)
		event, err := controlplane.NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), controlplane.RunEventTaskSkipped, task, 0, "", "", time.Time{}, "", controlplane.RunFailureDependency, time.Time{}, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.journal.Append(ctx, state.HeadIdentity(), event); err != nil {
			t.Fatal(err)
		}
	}
	if suffix == 4 {
		if _, err := f.coordinator.FailRun(ctx, plan, controlplane.RunFailurePolicy, at); err != nil {
			t.Fatal(err)
		}
	}
}
