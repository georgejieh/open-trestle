package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const localSourceOwnerLeaf = ".local-source-owner.json"

var (
	errLocalSourceOwnerPersistence = errors.New("local source owner persistence or changed state")
	errLocalSourceOwnerUnsupported = errors.New("local source owner directory identity unsupported")
)

func ownerPersistence(stage string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", errLocalSourceOwnerPersistence, stage)
	}
	return fmt.Errorf("%w: %s: %w", errLocalSourceOwnerPersistence, stage, err)
}

func ownerDirectoryInfo(info os.FileInfo) bool {
	return info != nil && info.Mode() == os.ModeDir|0700 && fileauthority.TrustedOwner(info)
}

// The path observations check cooperative consistency with the caller's opened root.
// Each checked root validates every existing component without following symlinks.
func observeLocalSourceDirectory(path string, root *os.Root) (localSourceDirectoryIdentity, error) {
	if root == nil || !validLocalOwnerPath(path) || filepath.Clean(path) != path {
		return localSourceDirectoryIdentity{}, ownerPersistence("absent or invalid opened root", nil)
	}
	before, err := checkedLocalSourceDirectoryInfo(path)
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("directory chain before", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("opened directory", err)
	}
	after, err := checkedLocalSourceDirectoryInfo(path)
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("directory chain after", err)
	}
	if !ownerDirectoryInfo(before) || !ownerDirectoryInfo(opened) || !ownerDirectoryInfo(after) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return localSourceDirectoryIdentity{}, ownerPersistence("directory identity or private mode changed", nil)
	}
	return localSourceDirectoryIdentityFromInfo(opened)
}

func checkedLocalSourceDirectoryInfo(path string) (os.FileInfo, error) {
	checked, err := localExistingRoot(path)
	if err != nil {
		return nil, err
	}
	if checked == nil {
		return nil, os.ErrNotExist
	}
	info, statErr := checked.Stat(".")
	closeErr := checked.Close()
	return info, errors.Join(statErr, closeErr)
}

// An opened artifact root must also match the exact child of its opened state root.
func observeLocalSourceArtifactDirectory(stateRoot, artifactRoot *os.Root, statePath string) (localSourceDirectoryIdentity, error) {
	return observeLocalSourceArtifactDirectoryWithHook(stateRoot, artifactRoot, statePath, nil)
}

// The per-call hook only arranges changes between child observations.
func observeLocalSourceArtifactDirectoryWithHook(stateRoot, artifactRoot *os.Root, statePath string, hook func(string)) (localSourceDirectoryIdentity, error) {
	if stateRoot == nil || artifactRoot == nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("absent artifact root", nil)
	}
	if _, err := observeLocalSourceDirectory(statePath, stateRoot); err != nil {
		return localSourceDirectoryIdentity{}, err
	}
	before, err := stateRoot.Lstat("artifacts")
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("artifact child before", err)
	}
	if hook != nil {
		hook("after-child-before")
	}
	identity, err := observeLocalSourceDirectory(filepath.Join(statePath, "artifacts"), artifactRoot)
	if err != nil {
		return localSourceDirectoryIdentity{}, err
	}
	opened, err := artifactRoot.Stat(".")
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("artifact opened", err)
	}
	after, err := stateRoot.Lstat("artifacts")
	if err != nil {
		return localSourceDirectoryIdentity{}, ownerPersistence("artifact child after", err)
	}
	if !ownerDirectoryInfo(before) || !ownerDirectoryInfo(after) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return localSourceDirectoryIdentity{}, ownerPersistence("artifact child changed", nil)
	}
	if _, err := observeLocalSourceDirectory(statePath, stateRoot); err != nil {
		return localSourceDirectoryIdentity{}, err
	}
	return identity, nil
}

func ownerLeafInfo(info os.FileInfo) bool {
	return info != nil && info.Mode() == 0600 && info.Mode().IsRegular() && fileauthority.TrustedOwner(info) && info.Size() > 0 && info.Size() <= maxLocalSourceOwnerRecordBytes
}

// readLocalSourceOwnerRecord reads one exact leaf without creating or modifying it.
func readLocalSourceOwnerRecord(root *os.Root, statePath string) (localSourceOwnerRecord, error) {
	record, _, _, err := readLocalSourceOwnerRecordDetails(root, statePath)
	return record, err
}

// Details retain the opened inode and bounded bytes for a separate publisher's post-link checks.
func readLocalSourceOwnerRecordDetails(root *os.Root, statePath string) (localSourceOwnerRecord, []byte, os.FileInfo, error) {
	return readLocalSourceOwnerRecordDetailsWithHook(root, statePath, nil)
}

// The optional per-call hook only arranges filesystem changes; it supplies no record or bytes.
func readLocalSourceOwnerRecordDetailsWithHook(root *os.Root, statePath string, hook func(string, *os.File)) (localSourceOwnerRecord, []byte, os.FileInfo, error) {
	return readLocalSourceOwnerRecordDetailsWithReadError(root, statePath, hook, nil)
}

// readFailure injects an error after reading the real file and before its close.
// It is per-call and cannot substitute bytes for the canonical read.
func readLocalSourceOwnerRecordDetailsWithReadError(root *os.Root, statePath string, hook func(string, *os.File), readFailure func() error) (localSourceOwnerRecord, []byte, os.FileInfo, error) {
	empty := localSourceOwnerRecord{}
	if _, err := observeLocalSourceDirectory(statePath, root); err != nil {
		return empty, nil, nil, err
	}
	before, err := root.Lstat(localSourceOwnerLeaf)
	if errors.Is(err, os.ErrNotExist) {
		if _, checkErr := observeLocalSourceDirectory(statePath, root); checkErr != nil {
			return empty, nil, nil, checkErr
		}
		return empty, nil, nil, fmt.Errorf("%w: %w", ErrLocalSourceOwnerMissing, err)
	}
	if err != nil {
		return empty, nil, nil, ownerPersistence("initial leaf lookup", err)
	}
	if !ownerLeafInfo(before) {
		return empty, nil, nil, ErrLocalSourceOwnerMalformed
	}
	if hook != nil {
		hook("before-open", nil)
	}
	file, err := root.Open(localSourceOwnerLeaf)
	if err != nil {
		return empty, nil, nil, ownerPersistence("leaf open", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil {
		closeErr := file.Close()
		return empty, nil, nil, errors.Join(ownerPersistence("opened leaf stat", statErr), ownerCloseError(closeErr))
	}
	if !ownerLeafInfo(opened) || !os.SameFile(before, opened) {
		closeErr := file.Close()
		if !ownerLeafInfo(opened) {
			return empty, nil, nil, errors.Join(ErrLocalSourceOwnerMalformed, ownerCloseError(closeErr))
		}
		return empty, nil, nil, errors.Join(ownerPersistence("leaf changed before open", nil), ownerCloseError(closeErr))
	}
	if hook != nil {
		hook("before-read", file)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxLocalSourceOwnerRecordBytes+1))
	if readFailure != nil {
		readErr = errors.Join(readErr, readFailure())
	}
	if hook != nil {
		hook("before-close", file)
	}
	closeErr := file.Close()
	if hook != nil {
		hook("before-after-lookup", nil)
	}
	after, lookupErr := root.Lstat(localSourceOwnerLeaf)
	_, rootErr := observeLocalSourceDirectory(statePath, root)
	var result error
	if readErr != nil {
		result = ownerPersistence("leaf read", readErr)
	}
	if closeErr != nil {
		result = errors.Join(result, ownerCloseError(closeErr))
	}
	if lookupErr != nil {
		result = errors.Join(result, ownerPersistence("leaf after read", lookupErr))
	} else if !ownerLeafInfo(after) {
		result = errors.Join(result, ErrLocalSourceOwnerMalformed)
	} else if !os.SameFile(before, after) || !os.SameFile(opened, after) {
		result = errors.Join(result, ownerPersistence("leaf changed after read", nil))
	}
	result = errors.Join(result, rootErr)
	if result != nil {
		return empty, nil, nil, result
	}
	if int64(len(raw)) != before.Size() || int64(len(raw)) != opened.Size() || int64(len(raw)) != after.Size() {
		return empty, nil, nil, ErrLocalSourceOwnerMalformed
	}
	record, err := decodeLocalSourceOwnerRecord(raw)
	if err != nil {
		return empty, nil, nil, err
	}
	return record, raw, opened, nil
}

func ownerCloseError(err error) error {
	if err == nil {
		return nil
	}
	return ownerPersistence("leaf close", err)
}
