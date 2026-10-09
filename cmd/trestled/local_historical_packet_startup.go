package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

var (
	errHistoricalPacketObservedAtStartup         = errors.New("historical packet observed at startup")
	errHistoricalPacketMissingAtStartup          = errors.New("historical packet missing at startup")
	errHistoricalPacketMismatchAtStartup         = errors.New("historical packet mismatch at startup")
	errHistoricalInputIntentQuarantinedAtStartup = errors.New("historical prepared context input intent quarantined at startup")
)

type historicalPacketStartupClass uint8

const (
	historicalPacketNone historicalPacketStartupClass = iota
	historicalPacketObserved
	historicalPacketMissing
	historicalPacketMismatch
	historicalPacketConservativeRefusal
	historicalPacketInputIntentQuarantined
)

type historicalGateFaultProbe struct {
	afterClassified   func(historicalPacketStartupClass) error
	closePhysicalFile func(*os.File) error
}

// This only classifies replayed intent and physically observed bytes for refusal.
// Neither the journal nor the owner checksum authenticates source/snapshot bytes.
func inspectRecordedHistoricalPackets(ctx context.Context, journal *controlplane.FileRunJournal, pending *artifact.PendingFileStore, recorded *localSourceOwnerRecordedSnapshot, statePath, artifactPath, setupPath string, expected *setup.Plan, tenant, repositoryID string, repository evidence.RepositoryIdentity, gitRoot *os.Root, originalGitIdentity localSourceDirectoryIdentity, objectStore *scm.LocalGitObjectStore, adapter *scm.LocalGitSourceAdapter, sourceDigest string, classification *historicalPacketStartupClass, probe *historicalGateFaultProbe) error {
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
				expectedPackets := make([]physicalPacketExpectation, 0, len(facts))
				for _, fact := range facts {
					if err := reconcileRecordedHistoricalFact(fact, tenant, repositoryID, sourceDigest); err != nil {
						return err
					}
					expectedPackets = append(expectedPackets, physicalPacketExpectation{scope: fact.Plan().Scope(), descriptor: fact.PreparedEvent().PacketDescriptor()})
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
					conservative := false
					linkedInput := false
					for i, observation := range observations {
						if observation.expectation.scope.Identity() != expectedPackets[i].scope.Identity() || observation.expectation.descriptor.ArtifactIdentity != expectedPackets[i].descriptor.ArtifactIdentity {
							return errPhysicalPacketObservationUncertain
						}
						switch observation.kind {
						case physicalPacketMissing:
							if selected != historicalPacketMissing && selected != historicalPacketMismatch {
								selected = historicalPacketMissing
							}
						case physicalPacketMismatch:
							if selected != historicalPacketMissing && selected != historicalPacketMismatch {
								selected = historicalPacketMismatch
							}
						case physicalPacketIntact:
							terminal, hasTerminal := facts[i].TerminalEvent()
							_, linked := facts[i].LinkedInputEvent()
							if linked {
								linkedInput = true
							} else if hasTerminal && terminal.Kind() == controlplane.RunEventCanceled {
								conservative = true
							}
						default:
							return errPhysicalPacketObservationUncertain
						}
					}
					if selected == historicalPacketObserved {
						switch {
						case linkedInput:
							selected = historicalPacketInputIntentQuarantined
						case conservative:
							selected = historicalPacketConservativeRefusal
						}
					}
					*classification = selected // Provisional until all postchecks and borrowed roots close.
					if probe != nil && probe.afterClassified != nil {
						return probe.afterClassified(selected)
					}
					return nil
				}
				if probe != nil && probe.closePhysicalFile != nil {
					return observeBorrowedHistoricalPacketFilesWithClose(ctx, artifactRoot, expectedPackets, after, probe.closePhysicalFile)
				}
				return observeBorrowedHistoricalPacketFiles(ctx, artifactRoot, expectedPackets, after)
			})
			if err != nil {
				return err
			}
			return recheck()
		})
	})
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
