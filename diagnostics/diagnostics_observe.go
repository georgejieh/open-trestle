package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// ObserveFileSet reads one stored diagnostic set through a borrowed private root.
// It neither acquires a writer nor changes files. The caller must retain and recheck
// root ownership; this observation does not authorize later effects.
func ObserveFileSet(ctx context.Context, root *os.Root, scope audit.ReviewScope) (Set, error) {
	return observeFileSet(ctx, root, scope, nil, (*os.File).Close)
}

// diagnosticSetFileName is the store leaf name for one scope.
func diagnosticSetFileName(scope audit.ReviewScope) string {
	return scope.Identity() + diagnosticSetSuffix
}

func observeFileSet(ctx context.Context, root *os.Root, scope audit.ReviewScope, afterRead func() error, closeFile func(*os.File) error) (Set, error) {
	if err := validateStoreOperation(ctx); err != nil {
		return Set{}, err
	}
	if root == nil || closeFile == nil {
		return Set{}, ErrInvalidStoreRoot
	}
	if err := scope.Validate(); err != nil {
		return Set{}, ErrInvalidSet
	}
	before, err := root.Stat(".")
	if err != nil || !privateDiagnosticsObserverRoot(before) {
		return Set{}, ErrInvalidStoreRoot
	}
	name := diagnosticSetFileName(scope)
	first, firstInfo, present, err := readObservedDiagnosticSet(ctx, root, name, closeFile)
	if err != nil {
		return Set{}, err
	}
	var value Set
	if present {
		value, err = ParseSet(first)
		if err != nil || value.Scope().Identity() != scope.Identity() {
			return Set{}, ErrCorruptStoreRecord
		}
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return Set{}, err
		}
	}
	second, secondInfo, stillPresent, err := readObservedDiagnosticSet(ctx, root, name, closeFile)
	if err != nil {
		return Set{}, err
	}
	if present != stillPresent {
		return Set{}, ErrCorruptStoreRecord
	}
	if present && (!sameObservedDiagnosticSet(firstInfo, secondInfo) || !bytes.Equal(first, second)) {
		return Set{}, ErrCorruptStoreRecord
	}
	after, err := root.Stat(".")
	if err != nil || !privateDiagnosticsObserverRoot(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return Set{}, ErrInvalidStoreRoot
	}
	if err := validateStoreOperation(ctx); err != nil {
		return Set{}, err
	}
	// An expected absence is reported only after the root and context checks pass,
	// so a caller that accepts absence never skips them.
	if !present {
		return Set{}, ErrSetNotFound
	}
	return value, nil
}

// privateDiagnosticsObserverRoot accepts only a private trusted directory.
func privateDiagnosticsObserverRoot(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0700 && fileauthority.TrustedOwner(info)
}

// privateDiagnosticsObserverFile accepts only a private trusted regular leaf.
func privateDiagnosticsObserverFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && fileauthority.TrustedOwner(info)
}

// sameObservedDiagnosticSet compares the identity metadata of one leaf.
func sameObservedDiagnosticSet(a, b os.FileInfo) bool {
	return privateDiagnosticsObserverFile(a) && privateDiagnosticsObserverFile(b) && os.SameFile(a, b) &&
		a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// readObservedDiagnosticSet reads one bounded leaf and reports the leaf metadata
// observed after the read, the close and the final name lookup.
func readObservedDiagnosticSet(ctx context.Context, root *os.Root, name string, closeFile func(*os.File) error) ([]byte, os.FileInfo, bool, error) {
	if err := validateStoreOperation(ctx); err != nil {
		return nil, nil, false, err
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, err)
	}
	if !privateDiagnosticsObserverFile(before) {
		return nil, nil, false, ErrCorruptStoreRecord
	}
	if before.Size() <= 0 || before.Size() > maxEncodedSetBytes {
		return nil, nil, false, ErrCorruptStoreRecord
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameObservedDiagnosticSet(before, opened) {
		return nil, nil, false, errors.Join(ErrCorruptStoreRecord, statErr, closeFile(file))
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, before.Size()+1))
	after, statErr := file.Stat()
	closeErr := closeFile(file)
	linked, linkErr := root.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, readErr, statErr, closeErr, linkErr)
	}
	if int64(len(raw)) != before.Size() || !sameObservedDiagnosticSet(before, after) || !sameObservedDiagnosticSet(before, linked) {
		return nil, nil, false, ErrCorruptStoreRecord
	}
	if err := validateStoreOperation(ctx); err != nil {
		return nil, nil, false, err
	}
	return raw, linked, true, nil
}
