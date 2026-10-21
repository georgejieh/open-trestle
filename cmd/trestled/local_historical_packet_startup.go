package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

var (
	errHistoricalPacketObservedAtStartup         = errors.New("historical packet observed at startup")
	errHistoricalPacketMissingAtStartup          = errors.New("historical packet missing at startup")
	errHistoricalPacketMismatchAtStartup         = errors.New("historical packet mismatch at startup")
	errHistoricalInputIntentQuarantinedAtStartup = errors.New("historical prepared context input intent quarantined at startup")
	errHistoricalInputArtifactMissingAtStartup   = errors.New("historical prepared context input artifact missing at startup")
)

type historicalPacketStartupClass uint8

const (
	historicalPacketNone historicalPacketStartupClass = iota
	historicalPacketObserved
	historicalPacketMissing
	historicalPacketMismatch
	historicalPacketConservativeRefusal
	historicalPacketInputIntentQuarantined
	historicalPacketInputArtifactMissing
	historicalPacketOwnerSettledCandidate
	historicalPacketOwnerPreparedCandidate
	historicalPacketExpiredV4Candidate
)

type historicalGateFaultProbe struct {
	afterClassified   func(historicalPacketStartupClass) error
	closePhysicalFile func(*os.File) error
}

// This only classifies replayed intent and physically observed bytes for refusal.
// Neither the journal nor the owner checksum authenticates source/snapshot bytes.
func inspectRecordedHistoricalPackets(ctx context.Context, journal *controlplane.FileRunJournal, pending *artifact.PendingFileStore, recorded *localSourceOwnerRecordedSnapshot, statePath, artifactPath, setupPath string, expected *setup.Plan, tenant, repositoryID string, repository evidence.RepositoryIdentity, gitRoot *os.Root, originalGitIdentity localSourceDirectoryIdentity, objectStore *scm.LocalGitObjectStore, adapter *scm.LocalGitSourceAdapter, sourceDigest string, classification *historicalPacketStartupClass, pendingV4 *[]historicalExpiredPacketCheckpoint, now time.Time, probe *historicalGateFaultProbe) error {
	return journal.WithOwnedHistoricalPacketFacts(ctx, func(stateRoot *os.Root, scan controlplane.HistoricalPacketScan) error {
		return pending.WithOwnedRoot(func(artifactRoot *os.Root) error {
			recheck := func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				stateID, err := observeLocalSourceDirectory(statePath, stateRoot)
				if err != nil {
					return err
				}
				artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
				if err != nil {
					return err
				}
				gitPath, err := filepath.Abs(gitRoot.Name())
				if err != nil {
					return err
				}
				gitID, err := observeLocalSourceDirectory(gitPath, gitRoot)
				if err != nil {
					return err
				}
				if gitID != originalGitIdentity {
					return ErrLocalSourceOwnerMismatch
				}
				if err = recheckLocalSourceOwnerRecordedSnapshot(ctx, recorded, stateRoot, artifactRoot); err != nil {
					return err
				}
				if err = inspectLockedOwnerSetupSemantics(ctx, setupPath, expected); err != nil {
					return err
				}
				observed := localSourceOwnerRecord{StatePath: statePath, ArtifactPath: artifactPath, GitObjectsPath: gitPath, TenantID: tenant, RepositoryID: repositoryID, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity(), Profile: string(objectStore.Profile()), SourcePathDigest: sourceDigest, Git: gitID, State: stateID, Artifact: artifactID}
				if err = observed.validate(); err != nil {
					return err
				}
				owner, err := readLocalSourceOwnerRecord(stateRoot, statePath)
				if err != nil {
					return err
				}
				return matchLocalSourceOwnerRecord(owner, observed)
			}
			if err := recheck(); err != nil {
				return err
			}
			err := scan(ctx, func(facts []controlplane.HistoricalContextPacketFact) error {
				sort.Slice(facts, func(i, j int) bool {
					left, right := facts[i].Plan().Scope().Identity(), facts[j].Plan().Scope().Identity()
					if left != right {
						return left < right
					}
					return facts[i].PreparedEvent().Sequence() < facts[j].PreparedEvent().Sequence()
				})
				if len(facts) > physicalPacketExpectationLimit {
					return errPhysicalPacketObservationUncertain
				}
				expectedPackets := make([]physicalPacketExpectation, 0, len(facts)*4)
				for _, fact := range facts {
					if err := reconcileRecordedHistoricalFact(fact, tenant, repositoryID, sourceDigest); err != nil {
						return err
					}
					expectedPackets = append(expectedPackets, physicalPacketExpectation{scope: fact.Plan().Scope(), descriptor: fact.PreparedEvent().PacketDescriptor()})
					if linked, ok := fact.LinkedInputEvent(); ok {
						if err := validateLinkedHistoricalInput(fact, linked); err != nil {
							return err
						}
						d := linked.InputDescriptor()
						scope := fact.Plan().Scope()
						expectedPackets = append(expectedPackets,
							physicalPacketExpectation{scope: scope, role: physicalRoleRequest, input: d.Request},
							physicalPacketExpectation{scope: scope, role: physicalRoleReceipt, input: d.Receipt},
							physicalPacketExpectation{scope: scope, role: physicalRoleInput, input: d.Input})
					}
				}
				if len(expectedPackets) == 0 {
					*classification = historicalPacketNone
					return nil
				}
				after := func(observations []physicalPacketObservation) error {
					if len(observations) != len(expectedPackets) {
						return errPhysicalPacketObservationUncertain
					}
					selected := historicalPacketObserved
					hasV4Missing := false
					hasV4Mismatch := false
					conservative := false
					linkedInput := false
					allMissingLinked := true
					allOwnerSettled := true
					allOwnerVersioned := true
					anyOwnerPrepared := false
					index := 0
					for _, fact := range facts {
						if index >= len(observations) || !reflect.DeepEqual(observations[index].expectation, expectedPackets[index]) {
							return errPhysicalPacketObservationUncertain
						}
						switch observations[index].kind {
						case physicalPacketMissing:
							hasV4Missing = true
						case physicalPacketMismatch:
							hasV4Mismatch = true
						case physicalPacketIntact:
							terminal, hasTerminal := fact.TerminalEvent()
							_, linked := fact.LinkedInputEvent()
							if !linked && hasTerminal && terminal.Kind() == controlplane.RunEventCanceled {
								conservative = true
							}
						default:
							return errPhysicalPacketObservationUncertain
						}
						if observations[index].kind != physicalPacketIntact {
							allOwnerSettled = false
							allOwnerVersioned = false
						}
						index++
						linked, hasLinked := fact.LinkedInputEvent()
						if !hasLinked {
							terminatedV4 := fact.ExpiryTail() == controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated && recordedV4PlanShape(fact.Plan()) && expiredPacketCheckpointValid(fact, now) == nil
							if !terminatedV4 {
								allOwnerSettled = false
								allOwnerVersioned = false
							}
						}
						if hasLinked {
							task, exists := fact.Plan().Task(linked.TaskKey())
							settlement, hasSettlement := fact.TaskSettlementEvent()
							terminal, hasTerminal := fact.TerminalEvent()
							settled := hasSettlement && settlement.Kind() == controlplane.RunEventContextInputSettled && settlement.PreviousIdentity() == linked.Identity() && settlement.OutputIdentity() == linked.InputDescriptor().Input.ArtifactIdentity && (!hasTerminal || terminal.Kind() == controlplane.RunEventSucceeded || terminal.Kind() == controlplane.RunEventCanceled)
							expiredTerminal := hasSettlement && settlement.Kind() == controlplane.RunEventTaskFailed && settlement.Failure() == controlplane.RunFailurePolicy && settlement.OutputIdentity() == "" && settlement.PreviousIdentity() == linked.Identity() && (!hasTerminal || terminal.Kind() == controlplane.RunEventFailed)
							settled = settled || expiredTerminal
							preparedHead := !hasSettlement && !hasTerminal && fact.FinalHeadIdentity() == linked.Identity()
							if !exists || task.HandlerIdentity() != contexthandler.PacketAuthorityHandlerIdentity() || !settled {
								allOwnerSettled = false
							}
							if !exists || task.HandlerIdentity() != contexthandler.PacketAuthorityHandlerIdentity() || !(settled || preparedHead) {
								allOwnerVersioned = false
							}
							if preparedHead {
								anyOwnerPrepared = true
							}
							linkedInput = true
							if index+3 > len(observations) {
								return errPhysicalPacketObservationUncertain
							}
							tripleMissing := true
							for offset := 0; offset < 3; offset++ {
								observed := observations[index+offset]
								if !reflect.DeepEqual(observed.expectation, expectedPackets[index+offset]) {
									return errPhysicalPacketObservationUncertain
								}
								switch observed.kind {
								case physicalPacketMissing:
									allOwnerSettled = false
									allOwnerVersioned = false
								case physicalPacketIntact:
									tripleMissing = false
								case physicalPacketMismatch:
									tripleMissing = false
									allOwnerSettled = false
									allOwnerVersioned = false
								default:
									return errPhysicalPacketObservationUncertain
								}
							}
							allMissingLinked = allMissingLinked && tripleMissing
							index += 3
						}
					}
					if index != len(observations) {
						return errPhysicalPacketObservationUncertain
					}
					anyUnlinked, anyLinked := false, false
					for _, fact := range facts {
						if _, linked := fact.LinkedInputEvent(); linked {
							anyLinked = true
						} else {
							anyUnlinked = true
						}
					}
					if anyUnlinked && anyLinked && !hasV4Missing && !hasV4Mismatch {
						if !allOwnerSettled {
							return errHistoricalPacketObservedAtStartup
						}
						for _, fact := range facts {
							if _, linked := fact.LinkedInputEvent(); linked {
								settled, exists := fact.TaskSettlementEvent()
								if !exists || settled.Kind() != controlplane.RunEventContextInputSettled {
									return errHistoricalPacketObservedAtStartup
								}
								continue
							}
							if fact.ExpiryTail() != controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated || !recordedV4PlanShape(fact.Plan()) || expiredPacketCheckpointValid(fact, now) != nil {
								return errHistoricalPacketObservedAtStartup
							}
							if err := observeBorrowedHistoricalRecordedV4Names(ctx, artifactRoot, fact, historicalRecordedSourceBinding{RootIdentity: sourceDigest, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity()}); err != nil {
								return err
							}
							*pendingV4 = append(*pendingV4, expiredPacketCheckpoint(fact))
						}
					}
					switch {
					case hasV4Missing:
						selected = historicalPacketMissing
					case hasV4Mismatch:
						selected = historicalPacketMismatch
					case linkedInput && allMissingLinked:
						selected = historicalPacketInputArtifactMissing
					case linkedInput && allOwnerSettled:
						selected = historicalPacketOwnerSettledCandidate
					case linkedInput && allOwnerVersioned && anyOwnerPrepared:
						selected = historicalPacketOwnerPreparedCandidate
					case linkedInput:
						selected = historicalPacketInputIntentQuarantined
					case conservative:
						selected = historicalPacketConservativeRefusal
					}
					eligibleExpiry := anyUnlinked
					for _, fact := range facts {
						if !recordedV4PlanShape(fact.Plan()) || expiredPacketCheckpointValid(fact, now) != nil {
							eligibleExpiry = false
						}
					}
					if selected == historicalPacketObserved {
						if eligibleExpiry {
							checkpoints := make([]historicalExpiredPacketCheckpoint, 0, len(facts))
							for _, fact := range facts {
								if err := expiredPacketCheckpointValid(fact, now); err != nil {
									return err
								}
								if err := observeBorrowedHistoricalRecordedV4Names(ctx, artifactRoot, fact, historicalRecordedSourceBinding{RootIdentity: sourceDigest, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity()}); err != nil {
									return err
								}
								checkpoints = append(checkpoints, expiredPacketCheckpoint(fact))
							}
							*pendingV4 = checkpoints
							selected = historicalPacketExpiredV4Candidate
						}
					}
					*classification = selected // Provisional until all postchecks and borrowed roots close.
					if probe != nil && probe.afterClassified != nil {
						return probe.afterClassified(selected)
					}
					return nil
				}
				closeFile := (*os.File).Close
				if probe != nil && probe.closePhysicalFile != nil {
					closeFile = probe.closePhysicalFile
				}
				return observeBorrowedHistoricalFilesWithClose(ctx, artifactRoot, expectedPackets, after, closeFile)
			})
			if err != nil {
				return err
			}
			return recheck()
		})
	})
}

// Replay supplies the link; recheck its identity and descriptor before naming leaves.
func validateLinkedHistoricalInput(f controlplane.HistoricalContextPacketFact, linked controlplane.RunEvent) error {
	plan, prepared := f.Plan(), f.PreparedEvent()
	d, packet := linked.InputDescriptor(), prepared.PacketDescriptor()
	if linked.Kind() != controlplane.RunEventContextInputPrepared || linked.Validate() != nil ||
		linked.PlanIdentity() != plan.Identity() || linked.Scope().Identity() != plan.Scope().Identity() ||
		linked.TaskKey() != prepared.TaskKey() || linked.TaskIdentity() != prepared.TaskIdentity() ||
		linked.Attempt() != prepared.Attempt() || linked.LeaseTokenIdentity() != prepared.LeaseTokenIdentity() ||
		linked.Sequence() <= prepared.Sequence() || linked.OutputIdentity() != d.Input.ArtifactIdentity ||
		d.PacketPreparedEventIdentity != prepared.Identity() || d.PacketArtifactIdentity != packet.ArtifactIdentity ||
		d.LeaseIdentity != packet.LeaseIdentity || d.LeaseEventIdentity != packet.LeaseEventIdentity ||
		d.Request.Classification != packet.Classification || d.Request.Protection != packet.Protection ||
		d.Request.Protection != "process_private" || d.Request.ExpiresAtMilliseconds != packet.ExpiresAtMilliseconds ||
		d.Request.CreatedAtMilliseconds < packet.CreatedAtMilliseconds ||
		d.Request.CreatedAtMilliseconds < prepared.OccurredAt().UnixMilli() ||
		d.Request.CreatedAtMilliseconds > linked.OccurredAt().UnixMilli() ||
		d.Receipt.CreatedAtMilliseconds > linked.OccurredAt().UnixMilli() ||
		d.Input.CreatedAtMilliseconds > linked.OccurredAt().UnixMilli() ||
		d.Input.ExpiresAtMilliseconds <= linked.OccurredAt().UnixMilli() {
		return errPhysicalPacketObservationUncertain
	}
	for role, desc := range []controlplane.ContextInputArtifactDescriptor{d.Request, d.Receipt, d.Input} {
		e := physicalPacketExpectation{scope: plan.Scope(), role: physicalPacketRole(role + 1), input: desc}
		if !physicalExpectationValid(e) {
			return errPhysicalPacketObservationUncertain
		}
	}
	return nil
}

func reconcileRecordedHistoricalFact(f controlplane.HistoricalContextPacketFact, tenant, repositoryID, sourceDigest string) error {
	plan, prepared := f.Plan(), f.PreparedEvent()
	scope := plan.Scope()
	if plan.Validate() != nil || prepared.Validate() != nil || scope.TenantID() != tenant || scope.RepositoryID() != repositoryID {
		return ErrLocalSourceOwnerMismatch
	}
	task, exists := plan.Task(prepared.TaskKey())
	descriptor := prepared.PacketDescriptor()
	if !exists || task.Kind() != controlplane.TaskAssembleContext || task.Identity() != prepared.TaskIdentity() ||
		prepared.Kind() != controlplane.RunEventContextPacketPrepared || prepared.PlanIdentity() != plan.Identity() ||
		prepared.Scope().Identity() != scope.Identity() || prepared.Attempt() == 0 || prepared.Attempt() > task.MaxAttempts() ||
		prepared.LeaseTokenIdentity() == "" || descriptor.LeaseIdentity == "" || descriptor.LeaseEventIdentity == "" ||
		descriptor.SourceRootIdentity != sourceDigest || prepared.OutputIdentity() != descriptor.ArtifactIdentity {
		return ErrLocalSourceOwnerMismatch
	}
	// The rooted journal replay validates the predecessor lease identity and event.
	// The fact API does not expose that predecessor event for a second comparison.
	upstream := f.UpstreamSuccessEvents()
	keys := task.Dependencies()
	if len(upstream) != len(keys) {
		return ErrLocalSourceOwnerMismatch
	}
	outputs := make([]string, 0, len(keys))
	for i, key := range keys {
		dependency, ok := plan.Task(key)
		event := upstream[i]
		if !ok || event.Kind() != controlplane.RunEventTaskSucceeded || event.TaskKey() != key || event.TaskIdentity() != dependency.Identity() || event.Scope().Identity() != scope.Identity() || event.PlanIdentity() != plan.Identity() || event.Sequence() >= prepared.Sequence() || event.Validate() != nil {
			return ErrLocalSourceOwnerMismatch
		}
		outputs = append(outputs, event.OutputIdentity())
	}
	sort.Strings(outputs)
	outputs = slices.Compact(outputs)
	if !slices.Equal(outputs, descriptor.DependencyIdentities) {
		return ErrLocalSourceOwnerMismatch
	}
	return nil
}
