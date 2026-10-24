package artifact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// ObserveFileArtifact reads one stored artifact through a borrowed private root.
// It neither acquires a writer nor changes files, and it makes no expiry decision:
// the caller reads ExpiresAt from the returned artifact. The caller must retain and
// recheck root ownership; this observation does not authorize later effects.
func ObserveFileArtifact(ctx context.Context, root *os.Root, scope audit.ReviewScope, identity string) (Artifact, error) {
	return observeFileArtifact(ctx, root, scope, identity, nil, (*os.File).Close)
}

// artifactFileName is the store leaf name for one scope and artifact identity.
func artifactFileName(scope audit.ReviewScope, identity string) string {
	return scope.Identity() + "-" + identity + artifactFileSuffix
}

func observeFileArtifact(ctx context.Context, root *os.Root, scope audit.ReviewScope, identity string, afterRead func() error, closeFile func(*os.File) error) (Artifact, error) {
	if err := validateContext(ctx); err != nil {
		return Artifact{}, err
	}
	if root == nil || closeFile == nil {
		return Artifact{}, ErrInvalidStoreRoot
	}
	if err := scope.Validate(); err != nil {
		return Artifact{}, ErrInvalidStore
	}
	if !validDigest(identity) {
		return Artifact{}, ErrInvalidStore
	}
	before, err := root.Stat(".")
	if err != nil || !privateArtifactObserverRoot(before) {
		return Artifact{}, ErrInvalidStoreRoot
	}
	name := artifactFileName(scope, identity)
	first, firstInfo, present, err := readObservedArtifactFile(ctx, root, name, closeFile)
	if err != nil {
		return Artifact{}, err
	}
	var value Artifact
	if present {
		value, err = Parse(first)
		if err != nil || value.Scope().Identity() != scope.Identity() || value.Identity() != identity {
			return Artifact{}, ErrCorruptArtifact
		}
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return Artifact{}, err
		}
	}
	second, secondInfo, stillPresent, err := readObservedArtifactFile(ctx, root, name, closeFile)
	if err != nil {
		return Artifact{}, err
	}
	if present != stillPresent {
		return Artifact{}, ErrCorruptArtifact
	}
	if present && (!sameObservedArtifactFile(firstInfo, secondInfo) || !bytes.Equal(first, second)) {
		return Artifact{}, ErrCorruptArtifact
	}
	after, err := root.Stat(".")
	if err != nil || !privateArtifactObserverRoot(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return Artifact{}, ErrInvalidStoreRoot
	}
	if err := validateContext(ctx); err != nil {
		return Artifact{}, err
	}
	// An expected absence is reported only after the root and context checks pass,
	// so a caller that accepts absence never skips them.
	if !present {
		return Artifact{}, ErrArtifactNotFound
	}
	return value, nil
}

// privateArtifactObserverRoot accepts only a private trusted directory.
func privateArtifactObserverRoot(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0700 && fileauthority.TrustedOwner(info)
}

// privateArtifactObserverFile accepts only a private trusted regular leaf.
func privateArtifactObserverFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && fileauthority.TrustedOwner(info)
}

// sameObservedArtifactFile compares the identity metadata of one leaf.
func sameObservedArtifactFile(a, b os.FileInfo) bool {
	return privateArtifactObserverFile(a) && privateArtifactObserverFile(b) && os.SameFile(a, b) &&
		a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// readObservedArtifactFile reads one bounded leaf and reports the leaf metadata
// observed after the read, the close and the final name lookup.
func readObservedArtifactFile(ctx context.Context, root *os.Root, name string, closeFile func(*os.File) error) ([]byte, os.FileInfo, bool, error) {
	return readObservedArtifactFileBounded(ctx, root, name, maxEncodedArtifactBytes, closeFile)
}
func readObservedArtifactFileBounded(ctx context.Context, root *os.Root, name string, limit int64, closeFile func(*os.File) error) ([]byte, os.FileInfo, bool, error) {
	if err := validateContext(ctx); err != nil {
		return nil, nil, false, err
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, err)
	}
	if !privateArtifactObserverFile(before) {
		return nil, nil, false, ErrCorruptArtifact
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, nil, false, ErrCorruptArtifact
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameObservedArtifactFile(before, opened) {
		return nil, nil, false, errors.Join(ErrCorruptArtifact, statErr, closeFile(file))
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, before.Size()+1))
	after, statErr := file.Stat()
	closeErr := closeFile(file)
	linked, linkErr := root.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil {
		return nil, nil, false, errors.Join(ErrStorePersistence, readErr, statErr, closeErr, linkErr)
	}
	if int64(len(raw)) != before.Size() || !sameObservedArtifactFile(before, after) || !sameObservedArtifactFile(before, linked) {
		return nil, nil, false, ErrCorruptArtifact
	}
	if err := validateContext(ctx); err != nil {
		return nil, nil, false, err
	}
	return raw, linked, true, nil
}
