package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// The routes declare 4097 context tokens with a 4096-token output allowance and
// a one-token declared input floor, so the pair resolves while the byte-based
// estimate of the actual request outgrows the route.
var refusingTestCapacity = localGenerationTestCapacity{context: 4097, output: 4096, minContext: 4097, estimatedInput: 1}

// The route refusal is found under the preflight gate and settled under a
// second one. A lease that expires between the two must not stop the owner:
// it settles the exact v4 as the lease-expiry termination instead.
func TestOwnerRouteRefusalLeaseExpiryBetweenGates(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"in-lease", "expires-between-gates"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			ctx := context.Background()
			scope := f.request.Plan().Scope()
			packet, err := f.owner.PreparePacket(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			inventory, policy, err := localGenerationInventoryAndPolicyWithCapacityForTest(ctx, t, strings.Repeat("e", 64), refusingTestCapacity)
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
			expired := localPacketFixtureClock{f.request.Lease().ExpiresAt().Add(time.Millisecond)}
			if mode == "expires-between-gates" {
				f.owner.beforeRouteRefusal = func() { f.owner.clock = expired }
			}
			prepared, err := f.owner.prepareAndSettleInputAfterPacket(ctx, f.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
			if err != nil || prepared.Prepared.Identity() != "" {
				t.Fatalf("owner did not settle the refused packet: %v", err)
			}
			head, present, err := f.journal.Head(ctx, scope)
			if err != nil || !present || head.Kind() != controlplane.RunEventTaskFailed || head.PreviousIdentity() != packet.Identity() || head.Failure() != controlplane.RunFailurePolicy || head.OutputIdentity() != "" {
				t.Fatalf("head=%v err=%v", head.Kind(), err)
			}
			wantReason := controlplane.TaskFailureReasonRouteContextInsufficient
			if mode == "expires-between-gates" {
				wantReason = 0
				if head.OccurredAt().Before(f.request.Lease().ExpiresAt()) {
					t.Fatal("termination is not after the lease")
				}
			} else if !head.OccurredAt().Before(f.request.Lease().ExpiresAt()) {
				t.Fatal("refusal is not within the lease")
			}
			if head.FailureReason() != wantReason {
				t.Fatalf("reason = %v, want %v", head.FailureReason(), wantReason)
			}
			facts, err := f.journal.InspectHistoricalContextPackets(ctx)
			if err != nil || len(facts) != 1 {
				t.Fatalf("facts=%d %v", len(facts), err)
			}
			wantTail := controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated
			if mode == "expires-between-gates" {
				wantTail = controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated
			}
			if facts[0].ExpiryTail() != wantTail {
				t.Fatalf("tail = %v, want %v", facts[0].ExpiryTail(), wantTail)
			}
		})
	}
}
