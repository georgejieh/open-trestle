package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

type failedOwnerExpirySanitizer struct {
	review.GenerationRequestSanitizer
	expire func()
}

func (s failedOwnerExpirySanitizer) SanitizeGeneration(ctx context.Context, request provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	s.expire()
	return review.SanitizedModelRequest{}, review.SanitizedEgressReceipt{}, errors.New("sanitizer refusal")
}

func TestOwnerPacketRecheckExpiryRefusals(t *testing.T) {
	for _, mode := range []string{"sanitizer-error", "canceled", "marker", "drift", "packet-prepare"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scope := f.request.Plan().Scope()
			inventory, policy, err := localGenerationInventoryAndPolicyWithReviewPolicyForTest(ctx, t, f.request.Plan().PolicyIdentity())
			if err != nil {
				t.Fatal(err)
			}
			pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := audit.NewFileLedger(filepath.Join(t.TempDir(), "audit"))
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			planner, err := contexthandler.NewJournaledPacketOnlyHandler(f.store, f.owner.clock, f.coordinator)
			if err != nil {
				t.Fatal(err)
			}
			callbacks := 0
			expire := func() { f.owner.clock = localPacketFixtureClock{f.request.Lease().ExpiresAt()} }
			callback := func() {
				callbacks++
				if callbacks != 1 {
					t.Fatal("repeated callback")
				}
				head, present, err := f.journal.Head(ctx, scope)
				if err != nil || !present || head.Kind() != controlplane.RunEventContextPacketPrepared {
					t.Fatalf("callback did not reach real v4: %v", err)
				}
				switch mode {
				case "canceled":
					cancel()
				case "marker":
					if err := os.WriteFile(filepath.Join(f.statePath, scope.Identity()+".scope-intent.json"), []byte("unresolved\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "drift":
					if _, err := f.coordinator.CancelRun(ctx, f.request.Plan(), f.owner.clock.Now()); err != nil {
						t.Fatal(err)
					}
				}
				expire()
			}
			var sanitizer review.GenerationRequestSanitizer = expireOwnerSanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), expire: callback}
			if mode == "sanitizer-error" {
				sanitizer = failedOwnerExpirySanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), expire: callback}
			}
			if mode == "packet-prepare" {
				f.owner.beforeRawPut = expire
			}
			handler := &localContextOwnerTask{owner: f.owner, ledger: ledger, sanitizer: sanitizer, configuration: policy, inventory: inventory, pair: pair, abstentionPlanner: planner}
			if err := handler.ExecuteAndSettle(ctx, f.request); err == nil {
				t.Fatal("unqualified failure was settled")
			}
			if mode == "packet-prepare" && callbacks != 0 || mode != "packet-prepare" && callbacks != 1 {
				t.Fatalf("unexpected callback count: %d", callbacks)
			}
			readCtx := context.Background()
			_, state, err := f.coordinator.Resume(readCtx, scope)
			if err != nil {
				t.Fatal(err)
			}
			task, found := state.Task("context")
			if !found || task.Status() == controlplane.TaskRuntimeFailed || task.OutputIdentity() != "" || state.Status() == controlplane.ReviewRunFailed {
				t.Fatal("refused case gained a failure disposition")
			}
			events, err := f.journal.Read(readCtx, scope, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Kind() == controlplane.RunEventTaskFailed || event.Kind() == controlplane.RunEventContextInputPrepared || event.Kind() == controlplane.RunEventContextInputSettled || event.Kind() == controlplane.RunEventFailed {
					t.Fatalf("refused case appended input/failure event: %v", event.Kind())
				}
			}
			auditEvents, err := ledger.Read(readCtx, scope, 0, 100)
			if err != nil || len(auditEvents) != 0 {
				t.Fatalf("refused case produced route evidence: count=%d err=%v", len(auditEvents), err)
			}
		})
	}
}

func TestOwnerPacketRecheckExpiryGateRefusals(t *testing.T) {
	for _, mode := range []string{"marker", "drift", "canceled", "clock-rollback", "zero-fact", "artifact-expired", "repeat", "finalized-repeat"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scope := f.request.Plan().Scope()
			packet, err := f.owner.PreparePacket(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			sanitizer := expireOwnerSanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), expire: func() { f.owner.clock = localPacketFixtureClock{f.request.Lease().ExpiresAt()} }}
			_, expiry, err := f.owner.sanitizePreparedPacket(ctx, f.request, packet, sanitizer)
			if err == nil || expiry.sampledAt.IsZero() {
				t.Fatalf("exact expiry witness absent: %v", err)
			}
			switch mode {
			case "marker":
				if err := os.WriteFile(filepath.Join(f.statePath, scope.Identity()+".scope-intent.json"), []byte("unresolved\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "drift":
				if _, err := f.coordinator.CancelRun(ctx, f.request.Plan(), f.owner.clock.Now()); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			case "clock-rollback":
				f.owner.clock = f.clock
			case "zero-fact":
				expiry = localPacketRecheckExpiry{}
			case "artifact-expired":
				f.owner.clock = localPacketFixtureClock{expiry.packet.Artifact().ExpiresAt()}
			case "repeat", "finalized-repeat":
				if err := f.owner.terminatePacketRecheckExpiry(ctx, f.request, packet, expiry); err != nil {
					t.Fatal(err)
				}
				if mode == "finalized-repeat" {
					finalizer, err := controlplane.NewRunFinalizer(f.journal)
					if err != nil {
						t.Fatal(err)
					}
					state, changed, err := finalizer.ReconcileRun(ctx, scope, f.owner.clock.Now())
					if err != nil || !changed || state.Status() != controlplane.ReviewRunFailed {
						t.Fatalf("finalize before repeat: changed=%v err=%v", changed, err)
					}
				}
			}
			before, present, err := f.journal.Head(context.Background(), scope)
			if err != nil || !present {
				t.Fatal(err)
			}
			if err := f.owner.terminatePacketRecheckExpiry(ctx, f.request, packet, expiry); err == nil {
				t.Fatal("stale or unqualified admission accepted")
			}
			after, present, err := f.journal.Head(context.Background(), scope)
			if err != nil || !present || before.Identity() != after.Identity() {
				t.Fatalf("refusal changed head: %v", err)
			}
		})
	}
}
