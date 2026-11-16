package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/internal/filelock"
	"github.com/georgejieh/open-trestle/internal/localownerroot"
)

// InspectRestoredJournal replays a closed journal without opening a writer,
// recovering effects, or granting startup or dispatch authority. Unresolved
// effect markers refuse inspection. Returned receipts are observations only.
// Inspection exclusively holds the existing cooperative writer lock; concurrent
// writers and other inspectors are refused, not blocked or retried.
func InspectRestoredJournal(ctx context.Context, path string) ([]ReviewRunReceipt, error) {
	var receipts []ReviewRunReceipt
	err := WithRestoredJournal(ctx, path, func(_ *os.Root, observed []ReviewRunReceipt) error { receipts = observed; return nil })
	if err != nil {
		return nil, err
	}
	return receipts, nil
}

// WithRestoredJournal retains the existing journal lock and rooted read witnesses
// across inspect. The callback must not write through or close the borrowed root,
// or retain it after the call. It must witness any sibling subtree it reads;
// journal witnesses do not cover subtree contents. Observations are provisional
// until this call returns nil and grant no startup or recovery authority.
func WithRestoredJournal(ctx context.Context, path string, inspect func(*os.Root, []ReviewRunReceipt) error) error {
	if inspect == nil {
		return ErrInvalidRunJournalEffectSection
	}
	_, err := inspectRestoredJournalWith(ctx, path, nil, inspect)
	return err
}

func inspectRestoredJournal(ctx context.Context, path string, afterLock func() error) ([]ReviewRunReceipt, error) {
	return inspectRestoredJournalWith(ctx, path, afterLock, nil)
}

func inspectRestoredJournalWith(ctx context.Context, path string, afterLock func() error, inspect func(*os.Root, []ReviewRunReceipt) error) (receipts []ReviewRunReceipt, err error) {
	if err := validateFileRunContext(ctx); err != nil {
		return nil, err
	}
	if !rootedScannerSupported() {
		return nil, ErrInvalidStartupInventoryEntry
	}
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, ErrInvalidRunJournalRoot
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, ErrInvalidRunJournalRoot
	}
	if err := checkOwnedJournalInfo(info, info); err != nil {
		return nil, errors.Join(ErrInvalidRunJournalRoot, err)
	}
	lock, err := filelock.AcquireExisting(filepath.Join(absolute, runJournalWriterLockName))
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return nil, errors.Join(ErrRunJournalLocked, err)
		}
		return nil, errors.Join(ErrInvalidStartupInventoryEntry, err)
	}
	defer func() {
		err = errors.Join(err, lock.Close())
		if err != nil {
			receipts = nil
		}
	}()
	if afterLock != nil {
		if err := afterLock(); err != nil {
			return nil, err
		}
	}
	root, err := localownerroot.ExistingRoot(absolute, ErrInvalidRunJournalRoot)
	if err != nil || root == nil {
		return nil, errors.Join(ErrInvalidRunJournalRoot, err)
	}
	defer func() {
		err = errors.Join(err, root.Close())
		if err != nil {
			receipts = nil
		}
	}()
	view := &FileRunJournal{root: absolute, rootInfo: info, closingSignal: make(chan struct{})}
	if err := view.rootedJournalValid(root); err != nil {
		return nil, errors.Join(ErrInvalidRunJournalRoot, err)
	}
	entries, err := enumerateRooted(root)
	if err != nil {
		return nil, err
	}
	if entry, ok := entries[runJournalWriterLockName]; !ok || !lock.SameFile(entry.info) {
		return nil, ErrInvalidStartupInventoryEntry
	}
	for name := range entries {
		if strings.HasSuffix(name, scopeIntentSuffix) {
			return nil, ErrScopeIntentUnresolved
		}
	}
	result, initial, witnesses, err := readRootedInventory(ctx, root, true)
	if err != nil {
		return nil, err
	}
	if err := compareRootedEntries(entries, initial); err != nil {
		return nil, err
	}
	var observationErr error
	if inspect != nil {
		observationErr = inspect(root, result.receipts)
	}
	finalErr := view.rootedFinal(ctx, root, initial, witnesses)
	current, err := root.Lstat(runJournalWriterLockName)
	if err != nil || rootedEntryValid(runJournalWriterLockName, current) != nil || !lock.SameFile(current) {
		finalErr = errors.Join(finalErr, ErrInvalidStartupInventoryEntry)
	}
	if err := errors.Join(observationErr, finalErr); err != nil {
		return nil, err
	}
	return result.receipts, nil
}
