package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/controlplane"
)

// Results remain provisional until the owned journal, snapshot and roots close.
func observeOwnerGenerationRejections(ctx context.Context, owner *localPacketOwner, checkGit func() error) (facts []controlplane.HistoricalContextPacketFact, rejected map[string]string, windows []generationRejectionWindow, result error) {
	snapshot, err := inspectLocalSourceOwnerRecordedSnapshot(ctx, owner.statePath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		result = errors.Join(result, snapshot.Close(), checkGit())
		for _, window := range windows {
			if !window.live(owner.clock.Now().UTC()) {
				result = errors.Join(result, errHistoricalInputIntentQuarantinedAtStartup)
			}
		}
		if result != nil {
			facts, rejected, windows = nil, nil, nil
		}
	}()
	rejected = make(map[string]string)
	result = owner.journal.WithOwnedHistoricalPacketFacts(ctx, func(stateRoot *os.Root, scan controlplane.HistoricalPacketScan) (result error) {
		artifactRoot, err := stateRoot.OpenRoot("artifacts")
		if err != nil {
			return err
		}
		recheck := func() error {
			if err := checkGit(); err != nil {
				return err
			}
			if err := recheckLocalSourceOwnerRecordedSnapshot(ctx, snapshot, stateRoot, artifactRoot); err != nil {
				return err
			}
			stateID, err := observeLocalSourceDirectory(owner.statePath, stateRoot)
			if err != nil {
				return err
			}
			artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, owner.statePath)
			if err != nil {
				return err
			}
			record, err := readLocalSourceOwnerRecord(stateRoot, owner.statePath)
			if err != nil {
				return err
			}
			if record.StatePath != owner.statePath || record.ArtifactPath != filepath.Join(owner.statePath, "artifacts") || record.SourcePathDigest != owner.sourceRootDigest || record.RepositoryIdentity != owner.sourceBinding.RepositoryIdentity || record.AdapterIdentity != owner.sourceBinding.AdapterIdentity || record.Git != owner.gitIdentity || record.State != stateID || record.Artifact != artifactID {
				return ErrLocalSourceOwnerMismatch
			}
			return nil
		}
		defer func() { result = errors.Join(result, recheck(), artifactRoot.Close()) }()
		if err := recheck(); err != nil {
			return err
		}
		return scan(ctx, func(observed []controlplane.HistoricalContextPacketFact) error {
			for _, fact := range observed {
				terminal, hasTerminal := fact.TerminalEvent()
				settlement, hasSettlement := fact.TaskSettlementEvent()
				if hasTerminal && terminal.Kind() == controlplane.RunEventFailed && hasSettlement && settlement.Kind() == controlplane.RunEventContextInputSettled {
					window, err := owner.generationStartup.observe(ctx, stateRoot, artifactRoot, fact, owner.sourceBinding, owner.clock.Now().UTC())
					if err != nil {
						return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
					}
					rejected[fact.Plan().Scope().Identity()] = fact.FinalHeadIdentity()
					windows = append(windows, window)
				}
			}
			facts = append(facts, observed...)
			return nil
		})
	})
	return facts, rejected, windows, result
}
