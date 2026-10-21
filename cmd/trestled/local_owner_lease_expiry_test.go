package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerExpiredMarkerFreeV5TerminatesAtRestart(t *testing.T) {
	t.Parallel()
	fixture := newLocalPacketOwnerFixture(t)
	ctx := context.Background()
	scope := fixture.request.Plan().Scope()
	packet, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(t.TempDir(), "audit")
	ledger, err := audit.NewFileLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.owner.PrepareInput(ctx, fixture.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.resources.Close(); err != nil {
		t.Fatal(err)
	}
	restart := &daemon{}
	defer restart.Close()
	clock := localPacketFixtureClock{fixture.request.Lease().ExpiresAt().Add(time.Millisecond)}
	_, journal, owner, err := startLocalSourceOwnerGate(ctx, restart, fixture.statePath, fixture.setupPath, &fixture.setupPlan, "tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, clock)
	if err != nil {
		t.Fatalf("expired marker-free v5 must remain recoverable for exact no-output termination: %v", err)
	}
	ledger, err = audit.NewFileLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := verifyOwnerSettledStartup(ctx, owner, ledger, fixture.gitRoot); err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := state.Task("context")
	if task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != "" || task.Failure() != controlplane.RunFailurePolicy {
		t.Fatalf("expired v5 task status=%s failure=%s", task.Status(), task.Failure())
	}
	if _, err := owner.store.Get(ctx, scope, prepared.Input.Identity(), clock.Now()); err != nil {
		t.Fatal("termination lost evidence:", err)
	}
	finalizer, _ := controlplane.NewRunFinalizer(journal)
	if _, _, err := finalizer.ReconcileRun(ctx, scope, clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restart.Close(); err != nil {
		t.Fatal(err)
	}
	second := &daemon{}
	defer second.Close()
	_, _, secondOwner, err := startLocalSourceOwnerGate(ctx, second, fixture.statePath, fixture.setupPath, &fixture.setupPlan, "tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, clock)
	if err != nil {
		t.Fatal("terminated v5 restart refused:", err)
	}
	secondLedger, err := audit.NewFileLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer secondLedger.Close()
	if err := verifyOwnerSettledStartup(ctx, secondOwner, secondLedger, fixture.gitRoot); err != nil {
		t.Fatal("terminal restart proof:", err)
	}
}

func TestOwnerInputExpiryBoundaries(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"before-v4", "before-input-put", "after-request-put", "after-receipt-put", "complete-v5", "unrelated-marker", "combined", "expired-settlement-marker"} {
		t.Run(name, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			ctx := context.Background()
			scope := f.request.Plan().Scope()
			expired := localPacketFixtureClock{f.request.Lease().ExpiresAt().Add(time.Millisecond)}
			if name == "before-v4" {
				f.owner.clock = expired
				if _, err := f.owner.PreparePacket(ctx, f.request); err == nil {
					t.Fatal("expired packet accepted")
				}
				if _, err := os.Lstat(filepath.Join(f.statePath, scope.Identity()+".scope-intent.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("preflight created marker", err)
				}
				return
			}
			packet, err := f.owner.PreparePacket(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
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
			partial := name == "before-input-put" || name == "after-request-put" || name == "after-receipt-put"
			if partial {
				calls := 0
				if name == "after-request-put" {
					calls = 1
				}
				if name == "after-receipt-put" {
					calls = 2
				}
				f.owner.beforeInputPut = func() {
					f.owner.clock = &ownerPutExpiryClock{at: f.clock.Now(), expired: expired.Now(), remaining: calls}
				}
			}
			var prepared localPreparedContextInput
			if name == "combined" {
				prepared, err = f.owner.PrepareAndSettleInput(ctx, f.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
			} else {
				prepared, err = f.owner.PrepareInput(ctx, f.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
			}
			marker := filepath.Join(f.statePath, scope.Identity()+".scope-intent.json")
			if partial {
				if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
					t.Fatal("known partial must retain proof marker", err)
				}
				_, state, resumeErr := f.coordinator.Resume(ctx, scope)
				if resumeErr != nil {
					t.Fatal(resumeErr)
				}
				task, _ := state.Task("context")
				if task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != "" || task.Failure() != controlplane.RunFailurePolicy {
					t.Fatal("partial expiry did not fail closed")
				}
				if _, err := os.Lstat(marker); err != nil {
					t.Fatal("partial marker lost", err)
				}
				if _, err := f.journal.TerminateExpiredOwnerContextInput(ctx, f.store, ledger, scope, expired); err == nil {
					t.Fatal("partial restart proof accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "combined" {
				head, _, err := f.journal.Head(ctx, scope)
				if err != nil || head.Kind() != controlplane.RunEventContextInputSettled {
					t.Fatal("combined did not append v6", err)
				}
				completion, _ := controlplane.NewTaskSuccess(strings.Repeat("a", 64))
				if _, err := f.coordinator.CompleteTask(ctx, f.request.Plan(), f.request.Lease(), completion, f.clock.Now()); err == nil {
					t.Fatal("generic mismatched success accepted")
				}
				if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("combined marker retained", err)
				}
				return
			}
			if name == "unrelated-marker" {
				bytes := []byte("{\"version\":1,\"scope\":\"" + scope.Identity() + "\",\"kind\":\"unrelated\",\"expected\":\"" + strings.Repeat("a", 64) + "\"}\n")
				if err := os.WriteFile(marker, bytes, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := f.journal.TerminateExpiredOwnerContextInput(ctx, f.store, ledger, scope, expired); err == nil {
					t.Fatal("unrelated marker cleared")
				}
				after, err := os.ReadFile(marker)
				if err != nil || string(after) != string(bytes) {
					t.Fatal("unrelated marker changed")
				}
				return
			}
			if name == "expired-settlement-marker" {
				clock := &expireOwnerSettlementClock{at: f.clock.Now(), expired: expired.Now()}
				_, err = f.journal.SettleOwnerContextInput(ctx, f.store, ledger, controlplane.OwnerContextInputSettlement{Plan: f.request.Plan(), Lease: f.request.Lease(), Prepared: prepared.Prepared, Packet: prepared.Packet, Request: prepared.Request, Receipt: prepared.Receipt, Input: prepared.Input, Clock: clock})
				if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
					t.Fatal("expiry during settlement did not retain marker", err)
				}
			}
			state, err := f.journal.TerminateExpiredOwnerContextInput(ctx, f.store, ledger, scope, expired)
			if err != nil {
				t.Fatal(err)
			}
			task, _ := state.Task("context")
			if task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != "" {
				t.Fatal("expired v5 promoted")
			}
			if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("complete abort marker retained", err)
			}
			if _, err := f.store.Get(ctx, scope, prepared.Input.Identity(), expired.Now()); err != nil {
				t.Fatal("evidence removed", err)
			}
			finalizer, _ := controlplane.NewRunFinalizer(f.journal)
			if _, _, err := finalizer.ReconcileRun(ctx, scope, expired.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := f.journal.TerminateExpiredOwnerContextInput(ctx, f.store, ledger, scope, expired); err != nil {
				t.Fatal("legal scheduler suffix rejected", err)
			}
		})
	}
}

type expireOwnerSettlementClock struct {
	at, expired time.Time
	calls       int
}

func (c *expireOwnerSettlementClock) Now() time.Time {
	c.calls++
	if c.calls >= 2 {
		return c.expired
	}
	return c.at
}

func TestOwnerSanitizerExpiryKeepsV4AndGrantsNoRoute(t *testing.T) {
	t.Parallel()
	f := newLocalPacketOwnerFixture(t)
	ctx := context.Background()
	scope := f.request.Plan().Scope()
	packet, err := f.owner.PreparePacket(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
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
	sanitizer := expireOwnerSanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), expire: func() { f.owner.clock = localPacketFixtureClock{f.request.Lease().ExpiresAt().Add(time.Millisecond)} }}
	if _, err := f.owner.PrepareAndSettleInput(ctx, f.request, packet, sanitizer, policy, inventory, pair, ledger, policy.ReviewPolicyIdentity()); err == nil {
		t.Fatal("sanitizer expiry accepted")
	}
	head, _, err := f.journal.Head(ctx, scope)
	if err != nil || head.Identity() != packet.Identity() {
		t.Fatal("sanitizer advanced v4", err)
	}
	events, err := ledger.Read(ctx, scope, 0, 10)
	if err != nil || len(events) != 0 {
		t.Fatal("expired sanitizer granted route", err)
	}
}

type expireOwnerSanitizer struct {
	review.GenerationRequestSanitizer
	expire func()
}

func (s expireOwnerSanitizer) PublicationContentScanner() review.PublicationContentScanner {
	return publicationContentScannerFromGenerationSanitizer(s.GenerationRequestSanitizer)
}

func (s expireOwnerSanitizer) SanitizeGeneration(ctx context.Context, request provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	sanitized, receipt, err := s.GenerationRequestSanitizer.SanitizeGeneration(ctx, request, scope)
	s.expire()
	return sanitized, receipt, err
}

type ownerPutExpiryClock struct {
	at, expired time.Time
	remaining   int
}

func (c *ownerPutExpiryClock) Now() time.Time {
	if c.remaining <= 0 {
		return c.expired
	}
	c.remaining--
	return c.at
}

func TestOwnerExpiredTerminalStartupRejectsInvalidAuditParents(t *testing.T) {
	t.Parallel()
	for _, mutation := range []string{"extra", "wrong-routing", "missing-selected"} {
		t.Run(mutation, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			ctx := context.Background()
			scope := f.request.Plan().Scope()
			packet, err := f.owner.PreparePacket(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
			if err != nil {
				t.Fatal(err)
			}
			ledgerPath := filepath.Join(t.TempDir(), "audit")
			ledger, err := audit.NewFileLedger(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := f.owner.PrepareInput(ctx, f.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
			if err != nil {
				t.Fatal(err)
			}
			expired := localPacketFixtureClock{f.request.Lease().ExpiresAt().Add(time.Millisecond)}
			if _, err := f.journal.TerminateExpiredOwnerContextInput(ctx, f.store, ledger, scope, expired); err != nil {
				t.Fatal(err)
			}
			original, err := ledger.Read(ctx, scope, 0, 10)
			if err != nil || len(original) != 1 {
				t.Fatal("audit fixture", err)
			}
			event := original[0]
			parents := event.CausalParentIdentities()
			d := prepared.Prepared.Descriptor()
			switch mutation {
			case "extra":
				parents = append(parents, strings.Repeat("0", 64))
			case "wrong-routing":
				for i, id := range parents {
					if id == d.RoutingInputIdentity {
						parents[i] = strings.Repeat("0", 64)
					}
				}
			case "missing-selected":
				for i, id := range parents {
					if id == d.SelectedRecordIdentity {
						parents = append(parents[:i], parents[i+1:]...)
						break
					}
				}
			}
			altered, err := audit.NewEvent(scope, event.Sequence(), event.PreviousIdentity(), event.Kind(), event.SubjectIdentity(), parents, time.UnixMilli(event.OccurredAtUnixMilliseconds()))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := audit.EncodeEvent(altered)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.resources.Close(); err != nil {
				t.Fatal(err)
			}
			auditPath := filepath.Join(ledgerPath, scope.Identity()+".audit.jsonl")
			if err := os.WriteFile(auditPath, append(encoded, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			streamPath := filepath.Join(f.statePath, scope.Identity()+".run.jsonl")
			streamBefore, err := os.ReadFile(streamPath)
			if err != nil {
				t.Fatal(err)
			}
			restart := &daemon{}
			defer restart.Close()
			_, _, owner, err := startLocalSourceOwnerGate(ctx, restart, f.statePath, f.setupPath, &f.setupPlan, "tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, expired)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err = audit.NewFileLedger(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			if err := verifyOwnerSettledStartup(ctx, owner, ledger, f.gitRoot); !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
				t.Fatalf("invalid terminal audit parents accepted: %v", err)
			}
			streamAfter, err := os.ReadFile(streamPath)
			if err != nil || !bytes.Equal(streamBefore, streamAfter) {
				t.Fatal("refusal mutated terminal journal", err)
			}
			auditAfter, err := os.ReadFile(auditPath)
			if err != nil || !bytes.Equal(auditAfter, append(encoded, '\n')) {
				t.Fatal("refusal mutated audit", err)
			}
			if _, err := os.Lstat(filepath.Join(f.statePath, scope.Identity()+".scope-intent.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created marker", err)
			}
		})
	}
}
