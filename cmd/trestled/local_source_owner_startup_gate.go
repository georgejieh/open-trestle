package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/fileauthority"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

// The constructors prepare and lock storage; only Activate can recover deletion receipts.
func startLocalSourceOwnerGate(ctx context.Context, resources *daemon, stateDirectory, setupPath string, expected *setup.Plan, tenant, repositoryID string, repository evidence.RepositoryIdentity, gitRoot *os.Root, objectStore *scm.LocalGitObjectStore, adapter *scm.LocalGitSourceAdapter, sourceDigest string) (*artifact.FileStore, *controlplane.FileRunJournal, error) {
	statePath, err := filepath.Abs(stateDirectory)
	if err != nil {
		return nil, nil, err
	}
	artifactPath := filepath.Join(statePath, "artifacts")
	gitEnabled := gitRoot != nil
	var originalGitIdentity localSourceDirectoryIdentity
	if gitEnabled {
		gitPath, pathErr := filepath.Abs(gitRoot.Name())
		if pathErr != nil {
			return nil, nil, pathErr
		}
		originalGitIdentity, err = observeLocalSourceDirectory(gitPath, gitRoot)
		if err != nil {
			return nil, nil, err
		}
	}
	var pending *artifact.PendingFileStore
	var journal *controlplane.FileRunJournal
	// Saved pre-constructor roots must close, successfully, before deletion recovery.
	preflight := func() (result error) {
		var snapshot *localSourceOwnerSnapshot
		var recorded *localSourceOwnerRecordedSnapshot
		var missing *localMissingStateBoundary
		var noGit *localNoGitOwnerPreflight
		defer func() {
			result = errors.Join(result, snapshot.Close(), recorded.Close(), missing.Close(), noGit.Close())
		}()
		if gitEnabled {
			// A present owner, even malformed, always takes the strict recorded path.
			_, lookupErr := os.Lstat(filepath.Join(statePath, localSourceOwnerLeaf))
			if lookupErr == nil {
				recorded, result = inspectLocalSourceOwnerRecordedSnapshot(ctx, statePath)
			} else if errors.Is(lookupErr, os.ErrNotExist) {
				snapshot, result = inspectLocalSourceOwnerSnapshot(ctx, statePath, setupPath, expected)
				if result == nil && snapshot.Kind == localSourceOwnerMissing {
					missing, result = captureLocalMissingStateBoundary(ctx, statePath)
				}
			} else {
				return errors.Join(ErrInvalidDaemonConfiguration, lookupErr)
			}
			if result != nil {
				return result
			}
			if snapshot != nil && snapshot.Kind != localSourceOwnerMissing {
				if result = recheckOwnerEntries(snapshot); result != nil {
					return result
				}
			}
			if missing != nil {
				if result = missing.RecheckMissing(ctx); result != nil {
					return result
				}
			}
		} else {
			noGit, result = inspectLocalNoGitOwnerPreflight(ctx, statePath)
			if result != nil {
				return result
			}
			if result = noGit.recheckBeforeConstructors(ctx); result != nil {
				return result
			}
		}
		if result = ctx.Err(); result != nil {
			return result
		}
		pending, result = artifact.OpenPendingFileStore(artifactPath)
		if result != nil {
			return result
		}
		resources.closers = append(resources.closers, pending)
		journal, result = controlplane.NewFileRunJournal(statePath)
		if result != nil {
			return result
		}
		resources.closers = append(resources.closers, journal)
		return journal.WithOwnedRoot(ctx, func(stateRoot *os.Root) error {
			return pending.WithOwnedRoot(func(artifactRoot *os.Root) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if noGit != nil {
					if gateErr := noGit.recheckConstructed(ctx, stateRoot, artifactRoot); gateErr != nil {
						return gateErr
					}
				}
				stateID, gateErr := observeLocalSourceDirectory(statePath, stateRoot)
				if gateErr != nil {
					return gateErr
				}
				artifactID, gateErr := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
				if gateErr != nil {
					return gateErr
				}
				if gitEnabled {
					gitPath, pathErr := filepath.Abs(gitRoot.Name())
					if pathErr != nil {
						return pathErr
					}
					gitID, identityErr := observeLocalSourceDirectory(gitPath, gitRoot)
					if identityErr != nil {
						return identityErr
					}
					if gitID != originalGitIdentity {
						return ErrLocalSourceOwnerMismatch
					}
					if recorded != nil {
						if gateErr = recheckLocalSourceOwnerRecordedSnapshot(ctx, recorded, stateRoot, artifactRoot); gateErr != nil {
							return gateErr
						}
						if gateErr = inspectLockedOwnerSetupSemantics(ctx, setupPath, expected); gateErr != nil {
							return gateErr
						}
					} else {
						if missing != nil {
							if gateErr = missing.RecheckConstructed(ctx, stateRoot); gateErr != nil {
								return gateErr
							}
						}
						if gateErr = recheckLocalSourceOwnerPostConstructor(snapshot, stateRoot, artifactRoot); gateErr != nil {
							return gateErr
						}
						if snapshot.Kind == localSourceOwnerSetupOnly {
							if gateErr = inspectLockedOwnerSetup(ctx, snapshot, stateRoot, artifactRoot, setupPath, expected); gateErr != nil {
								return gateErr
							}
						} else if gateErr = inspectLockedOwnerSetupSemantics(ctx, setupPath, expected); gateErr != nil {
							return gateErr
						}
					}
					observed := localSourceOwnerRecord{StatePath: statePath, ArtifactPath: artifactPath, GitObjectsPath: gitPath, TenantID: tenant, RepositoryID: repositoryID, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity(), Profile: string(objectStore.Profile()), SourcePathDigest: sourceDigest, Git: gitID, State: stateID, Artifact: artifactID}
					if gateErr = observed.validate(); gateErr != nil {
						return gateErr
					}
					if _, gateErr = journal.InspectStartupInventory(ctx); gateErr != nil {
						return localStartupInventoryError(gateErr)
					}
					if recorded != nil {
						owner, readErr := readLocalSourceOwnerRecord(stateRoot, statePath)
						if readErr != nil {
							return readErr
						}
						if gateErr = matchLocalSourceOwnerRecord(owner, observed); gateErr != nil {
							return gateErr
						}
						return recheckLocalSourceOwnerRecordedSnapshot(ctx, recorded, stateRoot, artifactRoot)
					}
					if gateErr = recheckLocalSourceOwnerPostConstructor(snapshot, stateRoot, artifactRoot); gateErr != nil {
						return gateErr
					}
					if missing != nil {
						if gateErr = missing.RecheckConstructed(ctx, stateRoot); gateErr != nil {
							return gateErr
						}
					}
					if gateErr = publishLocalSourceOwnerRecord(stateRoot, statePath, observed, nil); gateErr != nil {
						return gateErr
					}
					owner, readErr := readLocalSourceOwnerRecord(stateRoot, statePath)
					if readErr != nil {
						return readErr
					}
					if gateErr = matchLocalSourceOwnerRecord(owner, observed); gateErr != nil {
						return gateErr
					}
					return recheckLocalSourceOwnerPublishedShape(ctx, snapshot, missing, stateRoot, artifactRoot)
				}
				if _, gateErr = stateRoot.Lstat(localSourceOwnerLeaf); gateErr == nil {
					return fmt.Errorf("no-Git state has owner: %w", ErrLocalSourceOwnerMismatch)
				}
				if !errors.Is(gateErr, os.ErrNotExist) {
					return gateErr
				}
				if _, gateErr = journal.InspectStartupInventory(ctx); gateErr != nil {
					return localStartupInventoryError(gateErr)
				}
				if _, gateErr = stateRoot.Lstat(localSourceOwnerLeaf); gateErr == nil {
					return fmt.Errorf("no-Git state has owner: %w", ErrLocalSourceOwnerMismatch)
				}
				if !errors.Is(gateErr, os.ErrNotExist) {
					return gateErr
				}
				if gateErr = noGit.recheckConstructed(ctx, stateRoot, artifactRoot); gateErr != nil {
					return gateErr
				}
				_, gateErr = observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
				return gateErr
			})
		})
	}
	if err = preflight(); err != nil {
		return nil, nil, err
	}
	active, err := pending.Activate()
	if err != nil {
		return nil, nil, err
	}
	// Replace the already registered pending closer. The journal remains last.
	resources.closers[len(resources.closers)-2] = active
	return active, journal, nil
}

func inspectLockedOwnerSetup(ctx context.Context, s *localSourceOwnerSnapshot, stateRoot, artifactRoot *os.Root, path string, expected *setup.Plan) error {
	if err := recheckLocalSourceOwnerSetupBytes(ctx, s, stateRoot, artifactRoot); err != nil {
		return err
	}
	if err := inspectLockedOwnerSetupSemantics(ctx, path, expected); err != nil {
		return err
	}
	return recheckLocalSourceOwnerSetupBytes(ctx, s, stateRoot, artifactRoot)
}

func inspectLockedOwnerSetupSemantics(ctx context.Context, path string, expected *setup.Plan) error {
	inspected, err := setup.InspectStateFile(ctx, path)
	if err != nil {
		return err
	}
	posture := inspected.Posture()
	if expected == nil || inspected.Validate() != nil || inspected.RootIdentity() != expected.RootIdentity() || inspected.TenantID() != expected.TenantID() || inspected.RepositoryID() != expected.RepositoryID() || inspected.Profile() != setup.ProfileLocalSingleNode || inspected.Profile() != expected.Profile() || posture != expected.Posture() || posture.MetadataBackend() != setup.MetadataLocal || posture.ArtifactBackend() != setup.ArtifactLocal || posture.Egress() != setup.EgressDenied || posture.PublicationEnabled() || posture.DynamicValidationEnabled() {
		return errLocalSourceOwnerSnapshot
	}
	return nil
}

// Admit only the final leaf after publication; all original entries remain fixed.
func recheckLocalSourceOwnerPublishedShape(ctx context.Context, s *localSourceOwnerSnapshot, missing *localMissingStateBoundary, stateRoot, artifactRoot *os.Root) error {
	if ctx.Err() != nil || s == nil || stateRoot == nil || artifactRoot == nil {
		return errLocalSourceOwnerSnapshot
	}
	if missing != nil {
		if err := missing.RecheckConstructed(ctx, stateRoot); err != nil {
			return err
		}
	}
	if s.StateRoot != nil {
		original, err := s.StateRoot.Stat(".")
		current, currentErr := stateRoot.Stat(".")
		if err != nil || currentErr != nil || !ownerDirectoryInfo(current) || !os.SameFile(original, current) || !os.SameFile(s.Entries["."], current) || s.Entries["."].Mode() != current.Mode() {
			return errLocalSourceOwnerSnapshot
		}
	}
	required := map[string]bool{".run-writer.lock": false, "artifacts": false, localSourceOwnerLeaf: false}
	if s.Kind == localSourceOwnerSetupOnly {
		required["setup"] = false
	}
	entries, err := boundedOwnerEntries(stateRoot, len(required))
	if err != nil || len(entries) != len(required) {
		return errLocalSourceOwnerSnapshot
	}
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := required[name]; !ok || required[name] {
			return errLocalSourceOwnerSnapshot
		}
		required[name] = true
		info, statErr := stateRoot.Lstat(name)
		if statErr != nil {
			return errLocalSourceOwnerSnapshot
		}
		switch name {
		case localSourceOwnerLeaf:
			if !ownerLeafInfo(info) {
				return errLocalSourceOwnerSnapshot
			}
		case ".run-writer.lock":
			if !ownerConstructorLockInfo(info) {
				return errLocalSourceOwnerSnapshot
			}
		case "artifacts":
			child, rootErr := artifactRoot.Stat(".")
			if rootErr != nil || !ownerDirectoryInfo(info) || !recordedEqual(info, child) {
				return errLocalSourceOwnerSnapshot
			}
		case "setup":
			if !recordedEqual(s.Entries["setup"], info) {
				return errLocalSourceOwnerSnapshot
			}
		}
	}
	if s.Kind == localSourceOwnerSetupOnly {
		if err := recheckOriginalSetupSubtree(s); err != nil {
			return err
		}
		hashes, hashErr := hashOriginalSetupEntries(ctx, s)
		if hashErr != nil || !equalOriginalSetupBytes(s.SetupBytes, hashes) {
			return errLocalSourceOwnerSnapshot
		}
	}
	artifactEntries, err := boundedOwnerEntries(artifactRoot, 1)
	if err != nil || len(artifactEntries) != 1 || artifactEntries[0].Name() != ".artifact-writer.lock" {
		return errLocalSourceOwnerSnapshot
	}
	lock, err := artifactRoot.Lstat(".artifact-writer.lock")
	if err != nil || !ownerConstructorLockInfo(lock) {
		return errLocalSourceOwnerSnapshot
	}
	child, err := stateRoot.Lstat("artifacts")
	artifactInfo, artifactErr := artifactRoot.Stat(".")
	if err != nil || artifactErr != nil || !recordedEqual(child, artifactInfo) {
		return errLocalSourceOwnerSnapshot
	}
	if missing != nil {
		return missing.RecheckConstructed(ctx, stateRoot)
	}
	return ctx.Err()
}

func localStartupInventoryError(err error) error {
	if errors.Is(err, controlplane.ErrInvalidStartupInventoryEntry) {
		return fmt.Errorf("local metadata startup rejected: --state-dir has an invalid or unknown direct entry; review the documented private root layout offline; no automatic repair: %w", err)
	}
	return fmt.Errorf("local metadata startup inventory: %w", err)
}

// A no-Git boot may keep v3 runtime entries, but it must not let constructors
// chmod or traverse an unverified state/artifact path or accept an owner leaf.
type localNoGitOwnerPreflight struct {
	statePath               string
	stateRoot, artifactRoot *os.Root
	stateInfo, artifactInfo os.FileInfo
	statePin, artifactPin   *fileauthority.DirectoryPin
	missingState            *localNoGitMissingBoundary
	missingArtifact         bool
}

var errLocalNoGitPreflight = errors.New("no-Git local path or owner preflight refused")

func (s *localNoGitOwnerPreflight) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.artifactRoot != nil {
		err = errors.Join(err, s.artifactRoot.Close())
		s.artifactRoot = nil
	}
	if s.stateRoot != nil {
		err = errors.Join(err, s.stateRoot.Close())
		s.stateRoot = nil
	}
	err = errors.Join(err, s.missingState.Close())
	s.missingState = nil
	return err
}

func noGitOwnerAbsent(root *os.Root) error {
	if root == nil {
		return errLocalNoGitPreflight
	}
	_, err := root.Lstat(localSourceOwnerLeaf)
	if err == nil {
		return errors.Join(errLocalNoGitPreflight, ErrLocalSourceOwnerMismatch)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errLocalNoGitPreflight, err)
	}
	return nil
}

func inspectLocalNoGitOwnerPreflight(ctx context.Context, statePath string) (result *localNoGitOwnerPreflight, err error) {
	if ctx == nil || ctx.Err() != nil || !validLocalOwnerPath(statePath) {
		return nil, errLocalNoGitPreflight
	}
	s := &localNoGitOwnerPreflight{statePath: statePath}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
			result = nil
		}
	}()
	s.stateRoot, err = localExistingRoot(statePath)
	if err != nil {
		return nil, errors.Join(errLocalNoGitPreflight, err)
	}
	if s.stateRoot == nil {
		s.missingState, err = captureLocalNoGitMissingBoundary(ctx, statePath)
		if err != nil {
			return nil, errors.Join(errLocalNoGitPreflight, err)
		}
		if err = s.missingState.RecheckMissing(ctx); err != nil {
			return nil, errors.Join(errLocalNoGitPreflight, err)
		}
		s.missingArtifact = true
		return s, nil
	}
	s.statePin, err = fileauthority.PinDirectory(statePath)
	if err != nil {
		return nil, errors.Join(errLocalNoGitPreflight, err)
	}
	s.stateInfo, err = s.stateRoot.Stat(".")
	if err != nil || !ownerDirectoryInfo(s.stateInfo) {
		return nil, errors.Join(errLocalNoGitPreflight, err)
	}
	if err = noGitOwnerAbsent(s.stateRoot); err != nil {
		return nil, err
	}
	artifactPath := filepath.Join(statePath, "artifacts")
	s.artifactRoot, err = localExistingRoot(artifactPath)
	if err != nil {
		return nil, errors.Join(errLocalNoGitPreflight, err)
	}
	if s.artifactRoot == nil {
		if _, err = s.stateRoot.Lstat("artifacts"); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(errLocalNoGitPreflight, err)
		}
		s.missingArtifact = true
	} else {
		s.artifactPin, err = fileauthority.PinDirectory(artifactPath)
		if err != nil {
			return nil, errors.Join(errLocalNoGitPreflight, err)
		}
		s.artifactInfo, err = s.artifactRoot.Stat(".")
		child, childErr := s.stateRoot.Lstat("artifacts")
		if err != nil || childErr != nil || !ownerDirectoryInfo(s.artifactInfo) || !ownerDirectoryInfo(child) || !os.SameFile(s.artifactInfo, child) {
			return nil, errLocalNoGitPreflight
		}
	}
	if err = s.recheckBeforeConstructors(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *localNoGitOwnerPreflight) recheckBeforeConstructors(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return errLocalNoGitPreflight
	}
	if s.missingState != nil {
		return s.missingState.RecheckMissing(ctx)
	}
	if s.stateRoot == nil || s.statePin == nil || s.statePin.Recheck() != nil {
		return errLocalNoGitPreflight
	}
	state, err := s.stateRoot.Stat(".")
	named, namedErr := checkedLocalSourceDirectoryInfo(s.statePath)
	if err != nil || namedErr != nil || !ownerDirectoryInfo(state) || !os.SameFile(s.stateInfo, state) || !os.SameFile(state, named) || state.Mode() != s.stateInfo.Mode() || noGitOwnerAbsent(s.stateRoot) != nil {
		return errLocalNoGitPreflight
	}
	child, childErr := s.stateRoot.Lstat("artifacts")
	if s.missingArtifact {
		if !errors.Is(childErr, os.ErrNotExist) {
			return errLocalNoGitPreflight
		}
	} else {
		if childErr != nil || s.artifactRoot == nil || s.artifactPin == nil || s.artifactPin.Recheck() != nil || !ownerDirectoryInfo(child) || !os.SameFile(s.artifactInfo, child) {
			return errLocalNoGitPreflight
		}
		artifact, artifactErr := s.artifactRoot.Stat(".")
		namedArtifact, namedErr := checkedLocalSourceDirectoryInfo(filepath.Join(s.statePath, "artifacts"))
		if artifactErr != nil || namedErr != nil || !ownerDirectoryInfo(artifact) || !os.SameFile(s.artifactInfo, artifact) || !os.SameFile(artifact, namedArtifact) {
			return errLocalNoGitPreflight
		}
	}
	if s.statePin.Recheck() != nil || ctx.Err() != nil {
		return errLocalNoGitPreflight
	}
	return nil
}

func (s *localNoGitOwnerPreflight) recheckConstructed(ctx context.Context, stateRoot, artifactRoot *os.Root) error {
	if s == nil || ctx == nil || ctx.Err() != nil || stateRoot == nil || artifactRoot == nil {
		return errLocalNoGitPreflight
	}
	if s.missingState != nil {
		if err := s.missingState.RecheckConstructed(ctx, stateRoot); err != nil {
			return errors.Join(errLocalNoGitPreflight, err)
		}
	} else {
		if s.statePin.Recheck() != nil {
			return errLocalNoGitPreflight
		}
		original, err := s.stateRoot.Stat(".")
		borrowed, borrowErr := stateRoot.Stat(".")
		if err != nil || borrowErr != nil || !ownerDirectoryInfo(original) || !ownerDirectoryInfo(borrowed) || !os.SameFile(s.stateInfo, original) || !os.SameFile(original, borrowed) {
			return errLocalNoGitPreflight
		}
		named, namedErr := checkedLocalSourceDirectoryInfo(s.statePath)
		if namedErr != nil || !os.SameFile(named, borrowed) {
			return errLocalNoGitPreflight
		}
	}
	if err := noGitOwnerAbsent(stateRoot); err != nil {
		return err
	}
	child, childErr := stateRoot.Lstat("artifacts")
	borrowedArtifact, borrowErr := artifactRoot.Stat(".")
	if childErr != nil || borrowErr != nil || !ownerDirectoryInfo(child) || !ownerDirectoryInfo(borrowedArtifact) || !os.SameFile(child, borrowedArtifact) {
		return errLocalNoGitPreflight
	}
	if !s.missingArtifact {
		if s.artifactPin == nil || s.artifactRoot == nil || s.artifactPin.Recheck() != nil || !os.SameFile(s.artifactInfo, child) {
			return errLocalNoGitPreflight
		}
		original, err := s.artifactRoot.Stat(".")
		if err != nil || !os.SameFile(original, borrowedArtifact) {
			return errLocalNoGitPreflight
		}
	}
	if _, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, s.statePath); err != nil {
		return errors.Join(errLocalNoGitPreflight, err)
	}
	if s.statePin != nil && s.statePin.Recheck() != nil {
		return errLocalNoGitPreflight
	}
	if s.artifactPin != nil && s.artifactPin.Recheck() != nil {
		return errLocalNoGitPreflight
	}
	if s.missingState != nil {
		return s.missingState.RecheckConstructed(ctx, stateRoot)
	}
	return noGitOwnerAbsent(stateRoot)
}

// The inventory's exact owner-leaf exception is only useful to the all-local
// owner gate. Reject it in local-metadata/nonlocal-artifact mode before effects.
func rejectMixedLocalOwner(stateDirectory string) (result error) {
	path, err := filepath.Abs(stateDirectory)
	if err != nil {
		return err
	}
	root, err := localExistingRoot(path)
	if err != nil {
		return err
	}
	if root == nil {
		return nil
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return noGitOwnerAbsent(root)
}

// A missing no-Git state may be created below a trusted, non-writable 0755
// parent; unlike Git enrollment it need not demand a 0700 parent.
type localNoGitMissingBoundary struct {
	statePath, parentPath string
	parentRoot            *os.Root
	parentInfo            os.FileInfo
	pin                   *fileauthority.DirectoryPin
	suffix                []string
}

func (b *localNoGitMissingBoundary) Close() error {
	if b == nil || b.parentRoot == nil {
		return nil
	}
	root := b.parentRoot
	b.parentRoot = nil
	return root.Close()
}
func captureLocalNoGitMissingBoundary(ctx context.Context, statePath string) (result *localNoGitMissingBoundary, err error) {
	if ctx == nil || ctx.Err() != nil || !validLocalOwnerPath(statePath) {
		return nil, errLocalNoGitPreflight
	}
	path := statePath
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return nil, errLocalNoGitPreflight
		}
		before, statErr := os.Lstat(parent)
		if errors.Is(statErr, os.ErrNotExist) {
			path = parent
			continue
		}
		if statErr != nil {
			return nil, errors.Join(errLocalNoGitPreflight, statErr)
		}
		pin, pinErr := fileauthority.PinDirectory(parent)
		if pinErr != nil {
			return nil, errors.Join(errLocalNoGitPreflight, pinErr)
		}
		root, openErr := os.OpenRoot(parent)
		if openErr != nil {
			return nil, errors.Join(errLocalNoGitPreflight, openErr)
		}
		boundary := &localNoGitMissingBoundary{statePath: statePath, parentPath: parent, parentRoot: root, pin: pin}
		defer func() {
			if err != nil {
				err = errors.Join(err, boundary.Close())
				result = nil
			}
		}()
		opened, openedErr := root.Stat(".")
		after, afterErr := os.Lstat(parent)
		if openedErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || pin.Recheck() != nil {
			return nil, errLocalNoGitPreflight
		}
		boundary.parentInfo, err = root.Stat(".")
		named, namedErr := os.Lstat(parent)
		if err != nil || namedErr != nil || boundary.parentInfo.Mode().Perm()&0022 != 0 || !fileauthority.TrustedOwner(boundary.parentInfo) || !os.SameFile(boundary.parentInfo, named) {
			return nil, errLocalNoGitPreflight
		}
		remainder, relErr := filepath.Rel(parent, statePath)
		if relErr != nil || remainder == "." || remainder == ".." || filepath.IsAbs(remainder) {
			return nil, errLocalNoGitPreflight
		}
		boundary.suffix = filepathSplitNoGitSuffix(remainder)
		if len(boundary.suffix) == 0 || len(boundary.suffix) > 64 {
			return nil, errLocalNoGitPreflight
		}
		for _, name := range boundary.suffix {
			if !missingBoundaryComponent(name) {
				return nil, errLocalNoGitPreflight
			}
		}
		if err = boundary.RecheckMissing(ctx); err != nil {
			return nil, err
		}
		return boundary, nil
	}
}
func filepathSplitNoGitSuffix(path string) []string {
	var names []string
	for path != "." {
		parent, leaf := filepath.Split(path)
		if leaf == "" {
			break
		}
		names = append([]string{leaf}, names...)
		path = filepath.Clean(parent)
	}
	return names
}
func (b *localNoGitMissingBoundary) recheckParent(ctx context.Context) error {
	if b == nil || ctx == nil || ctx.Err() != nil || b.parentRoot == nil || b.pin == nil || b.pin.Recheck() != nil {
		return errLocalNoGitPreflight
	}
	opened, err := b.parentRoot.Stat(".")
	named, namedErr := os.Lstat(b.parentPath)
	if err != nil || namedErr != nil || !os.SameFile(opened, b.parentInfo) || !os.SameFile(named, b.parentInfo) || opened.Mode() != b.parentInfo.Mode() {
		return errLocalNoGitPreflight
	}
	return nil
}
func (b *localNoGitMissingBoundary) RecheckMissing(ctx context.Context) error {
	if err := b.recheckParent(ctx); err != nil {
		return err
	}
	first := b.suffix[0]
	if _, err := b.parentRoot.Lstat(first); !errors.Is(err, os.ErrNotExist) {
		return errLocalNoGitPreflight
	}
	if _, err := os.Lstat(filepath.Join(b.parentPath, first)); !errors.Is(err, os.ErrNotExist) {
		return errLocalNoGitPreflight
	}
	return b.recheckParent(ctx)
}
func (b *localNoGitMissingBoundary) RecheckConstructed(ctx context.Context, stateRoot *os.Root) (result error) {
	if stateRoot == nil || b.recheckParent(ctx) != nil {
		return errLocalNoGitPreflight
	}
	parent := b.parentRoot
	path := b.parentPath
	var children []*os.Root
	defer func() {
		for i := len(children) - 1; i >= 0; i-- {
			result = errors.Join(result, children[i].Close())
		}
	}()
	var final os.FileInfo
	for index, name := range b.suffix {
		path = filepath.Join(path, name)
		named, namedErr := os.Lstat(path)
		rooted, rootedErr := parent.Lstat(name)
		if namedErr != nil || rootedErr != nil || !ownerDirectoryInfo(named) || !os.SameFile(named, rooted) {
			return errLocalNoGitPreflight
		}
		child, err := parent.OpenRoot(name)
		if err != nil {
			return errors.Join(errLocalNoGitPreflight, err)
		}
		children = append(children, child)
		opened, openErr := child.Stat(".")
		if openErr != nil || !os.SameFile(named, opened) {
			return errLocalNoGitPreflight
		}
		if index+1 < len(b.suffix) {
			entries, entriesErr := boundedOwnerEntries(child, 1)
			if entriesErr != nil || len(entries) != 1 || entries[0].Name() != b.suffix[index+1] {
				return errLocalNoGitPreflight
			}
		} else {
			final = named
		}
		parent = child
	}
	borrowed, borrowErr := stateRoot.Stat(".")
	if borrowErr != nil || !ownerDirectoryInfo(borrowed) || !os.SameFile(final, borrowed) || b.recheckParent(ctx) != nil {
		return errLocalNoGitPreflight
	}
	return nil
}
