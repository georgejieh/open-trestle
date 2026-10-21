package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// The real current pipeline exists only after store and handler construction.
// Reobserve rejected histories before any recovery, admission or supervisor.
func verifyOwnerRejectedGenerationCatalog(ctx context.Context, owner *localPacketOwner, gitRoot *os.Root, catalog runtimecatalog.PipelineCatalog, policy string) error {
	if ctx == nil || owner == nil || owner.clock == nil || gitRoot == nil || catalog.Validate() != nil {
		return errHistoricalInputIntentQuarantinedAtStartup
	}
	checkGit := func() error {
		path, err := filepath.Abs(gitRoot.Name())
		if err != nil {
			return err
		}
		observed, err := observeLocalSourceDirectory(path, gitRoot)
		if err != nil || observed != owner.gitIdentity {
			return errors.Join(ErrLocalSourceOwnerMismatch, err)
		}
		return nil
	}
	facts, rejected, windows, err := observeOwnerGenerationRejections(ctx, owner, checkGit)
	if err != nil {
		return err
	}
	for _, fact := range facts {
		if rejected[fact.Plan().Scope().Identity()] != fact.FinalHeadIdentity() {
			continue
		}
		if fact.Plan().PolicyIdentity() != policy || validateEnrolledCatalog(fact.Plan(), catalog) != nil {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
	}
	if err := checkGit(); err != nil {
		return err
	}
	for _, window := range windows {
		if !window.live(owner.clock.Now().UTC()) {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
	}
	return nil
}
