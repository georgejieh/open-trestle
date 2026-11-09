package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

var errHistoricalPacketExpiryStartup = errors.New("historical packet expiry startup refused")

// These identities are provisional observations, never recovery authority.
type historicalExpiredPacketCheckpoint struct {
	scope                audit.ReviewScope
	plan, prepared, head string
	revision             uint64
}

func expiredPacketCheckpoint(f controlplane.HistoricalContextPacketFact) historicalExpiredPacketCheckpoint {
	return historicalExpiredPacketCheckpoint{f.Plan().Scope(), f.Plan().Identity(), f.PreparedEvent().Identity(), f.FinalHeadIdentity(), f.FinalRevision()}
}

// policyTerminatedV4Tail reports a packet-only preparation already settled by
// a no-output policy failure: a lease-expiry termination or an in-lease route
// refusal, each possibly followed by part of the closed cleanup suffix.
func policyTerminatedV4Tail(tail controlplane.ContextPacketExpiryTail) bool {
	return tail == controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated || tail == controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated
}

// expiredPacketCheckpointValid admits an exact or expiry-terminated v4 only
// after its original lease expired, and a refused v4 at any time, since its
// lease holder already settled it. Packet retention must remain live for all.
func expiredPacketCheckpointValid(f controlplane.HistoricalContextPacketFact, now time.Time) error {
	tail := f.ExpiryTail()
	leaseBound := tail == controlplane.ContextPacketExpiryTailActiveExactV4 || tail == controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated
	if !leaseBound && tail != controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated || now.UnixMilli() <= 0 || leaseBound && now.Before(f.LeaseEvent().LeaseExpiresAt()) || now.UnixMilli() >= f.PreparedEvent().PacketDescriptor().ExpiresAtMilliseconds {
		return errHistoricalPacketExpiryStartup
	}
	if _, linked := f.LinkedInputEvent(); linked {
		return errHistoricalPacketExpiryStartup
	}
	return nil
}

// All read-only witnesses finish outside WithScopeGate. The process owns the
// exclusive, unexposed boot stores; this is not protection against raw same-UID
// writes. No service or supervisor may run until this barrier returns.
func verifyOwnerExpiredPacketStartup(ctx context.Context, owner *localPacketOwner, ledger *audit.FileLedger, gitRoot *os.Root, catalog runtimecatalog.PipelineCatalog, policy string) error {
	if owner == nil || len(owner.pendingExpiredPackets) == 0 || owner.store == nil || owner.journal == nil || owner.clock == nil || ledger == nil || gitRoot == nil || ctx == nil {
		return errHistoricalPacketExpiryStartup
	}
	facts, heads, err := observeOwnerExpiredPackets(ctx, owner, ledger, gitRoot, catalog, policy)
	if err != nil {
		return err
	}
	checkpoints := make([]historicalExpiredPacketCheckpoint, len(facts))
	for i, f := range facts {
		checkpoints[i] = expiredPacketCheckpoint(f)
	}
	if !slices.Equal(checkpoints, owner.pendingExpiredPackets) {
		return errHistoricalPacketExpiryStartup
	}
	coordinator, err := controlplane.NewCoordinator(owner.journal)
	if err != nil {
		return err
	}
	for i, fact := range facts {
		if fact.ExpiryTail() != controlplane.ContextPacketExpiryTailActiveExactV4 {
			continue
		}
		expected := checkpoints[i]
		err = owner.journal.WithScopeGate(ctx, expected.scope, func(inner context.Context) error {
			plan, state, e := coordinator.Resume(inner, expected.scope)
			if e != nil {
				return e
			}
			at := owner.clock.Now().UTC()
			if plan.Identity() != expected.plan || state.HeadIdentity() != expected.head || state.Revision() != expected.revision || expiredPacketCheckpointValid(fact, at) != nil {
				return errHistoricalPacketExpiryStartup
			}
			runtime, ok := state.Task(fact.PreparedEvent().TaskKey())
			if !ok {
				return errHistoricalPacketExpiryStartup
			}
			packet, ok := runtime.PreparedContextPacket()
			if !ok || packet.Identity() != expected.prepared {
				return errHistoricalPacketExpiryStartup
			}
			next, e := coordinator.TerminatePreparedContextPacket(inner, plan, packet, at)
			if e != nil {
				return e
			}
			if next.Revision() != expected.revision+1 {
				return errHistoricalPacketExpiryStartup
			}
			checkpoints[i].head = next.HeadIdentity()
			checkpoints[i].revision = next.Revision()
			return nil
		})
		if err != nil {
			return err
		}
	}
	// Reproof is outside the scope gate to avoid the journal's nonreentrant gate.
	after, afterHeads, err := observeOwnerExpiredPackets(ctx, owner, ledger, gitRoot, catalog, policy)
	if err != nil || !slices.Equal(heads, afterHeads) || len(after) != len(checkpoints) {
		return errors.Join(errHistoricalPacketExpiryStartup, err)
	}
	for i, f := range after {
		// A termination appended above leaves the expiry tail; a refusal stays one.
		want := controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated
		if facts[i].ExpiryTail() == controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated {
			want = controlplane.ContextPacketExpiryTailRefusedV4PolicyTerminated
		}
		if expiredPacketCheckpoint(f) != checkpoints[i] || f.ExpiryTail() != want {
			return errHistoricalPacketExpiryStartup
		}
	}
	owner.pendingExpiredPackets = nil
	return nil
}

func observeOwnerExpiredPackets(ctx context.Context, owner *localPacketOwner, ledger *audit.FileLedger, gitRoot *os.Root, catalog runtimecatalog.PipelineCatalog, policy string) (facts []controlplane.HistoricalContextPacketFact, heads []localHistoricalPacketAuditHead, result error) {
	snapshot, err := inspectLocalSourceOwnerRecordedSnapshot(ctx, owner.statePath)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		result = errors.Join(result, snapshot.Close())
		if result != nil {
			facts = nil
			heads = nil
		}
	}()
	result = owner.journal.WithOwnedHistoricalPacketFacts(ctx, func(root *os.Root, scan controlplane.HistoricalPacketScan) error {
		recheck := func() error {
			if err := recheckLocalSourceOwnerRecordedSnapshot(ctx, snapshot, root, snapshot.ArtifactRoot); err != nil {
				return err
			}
			gitPath, err := filepath.Abs(gitRoot.Name())
			if err != nil {
				return err
			}
			gitID, err := observeLocalSourceDirectory(gitPath, gitRoot)
			if err != nil || gitID != owner.gitIdentity {
				return errors.Join(ErrLocalSourceOwnerMismatch, err)
			}
			record, err := readLocalSourceOwnerRecord(root, owner.statePath)
			if err != nil {
				return err
			}
			stateID, err := observeLocalSourceDirectory(owner.statePath, root)
			if err != nil {
				return err
			}
			artifactID, err := observeLocalSourceArtifactDirectory(root, snapshot.ArtifactRoot, owner.statePath)
			if err != nil {
				return err
			}
			if record.StatePath != owner.statePath || record.ArtifactPath != filepath.Join(owner.statePath, "artifacts") || record.GitObjectsPath != gitPath || record.State != stateID || record.Artifact != artifactID || record.Git != gitID || record.SourcePathDigest != owner.sourceBinding.RootIdentity || record.RepositoryIdentity != owner.sourceBinding.RepositoryIdentity || record.AdapterIdentity != owner.sourceBinding.AdapterIdentity {
				return ErrLocalSourceOwnerMismatch
			}
			for name := range snapshot.StateEntries {
				if strings.HasSuffix(name, ".scope-intent.json") {
					return controlplane.ErrScopeIntentUnresolved
				}
			}
			return nil
		}
		if err := recheck(); err != nil {
			return err
		}
		err := scan(ctx, func(observed []controlplane.HistoricalContextPacketFact) error {
			if len(observed) == 0 {
				return errHistoricalPacketExpiryStartup
			}
			sort.Slice(observed, func(i, j int) bool {
				left, right := observed[i].Plan().Scope().Identity(), observed[j].Plan().Scope().Identity()
				if left != right {
					return left < right
				}
				return observed[i].PreparedEvent().Sequence() < observed[j].PreparedEvent().Sequence()
			})
			for _, fact := range observed {
				if _, linked := fact.LinkedInputEvent(); linked {
					// Mixed startup admits only already settled owner scopes. Their
					// separate byte/audit proof ran before this read-only V4 proof.
					if !owner.settlementAuditVerified {
						return errHistoricalPacketExpiryStartup
					}
					continue
				}
				plan := fact.Plan()
				record, err := readLocalSourceOwnerRecord(root, owner.statePath)
				if err != nil {
					return err
				}
				if plan.Scope().TenantID() != record.TenantID || plan.Scope().RepositoryID() != record.RepositoryID {
					return ErrLocalSourceOwnerMismatch
				}
				if err := expiredPacketCheckpointValid(fact, owner.clock.Now().UTC()); err != nil {
					return err
				}
				if plan.PolicyIdentity() != policy || validateEnrolledCatalog(plan, catalog) != nil {
					return errHistoricalPacketExpiryStartup
				}
				if err := observeBorrowedHistoricalRecordedV4Names(ctx, snapshot.ArtifactRoot, fact, owner.sourceBinding); err != nil {
					return err
				}
				head, err := observeHistoricalPacketRouteAbsence(ctx, ledger, plan.Scope())
				if err != nil {
					return err
				}
				facts = append(facts, fact)
				heads = append(heads, head)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return recheck()
	})
	return facts, heads, result
}
