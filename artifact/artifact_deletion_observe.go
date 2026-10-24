package artifact

import (
	"bytes"
	"context"
	"os"

	"github.com/georgejieh/open-trestle/audit"
)

// ObserveFileDeletion reads one stored artifact deletion record through a borrowed
// private root. It neither acquires a writer nor changes files, and it never recovers
// or completes a deletion. The returned bool is the canonical completed flag from the
// on-disk record, which the caller must combine with the artifact's own presence:
// a record that is not completed, or a completed record whose artifact is still
// present, is an unfinished effect. The caller must retain and recheck root
// ownership; this observation does not authorize later effects.
func ObserveFileDeletion(ctx context.Context, root *os.Root, scope audit.ReviewScope, identity string) (DeletionReceipt, bool, error) {
	return observeFileDeletion(ctx, root, scope, identity, nil, (*os.File).Close)
}

// artifactDeletionFileName is the store leaf name for one deletion record.
func artifactDeletionFileName(scope audit.ReviewScope, identity string) string {
	return scope.Identity() + "-" + identity + deletionFileSuffix
}

func observeFileDeletion(ctx context.Context, root *os.Root, scope audit.ReviewScope, identity string, afterRead func() error, closeFile func(*os.File) error) (DeletionReceipt, bool, error) {
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, false, err
	}
	if root == nil || closeFile == nil {
		return DeletionReceipt{}, false, ErrInvalidStoreRoot
	}
	if err := scope.Validate(); err != nil {
		return DeletionReceipt{}, false, ErrInvalidStore
	}
	if !validDigest(identity) {
		return DeletionReceipt{}, false, ErrInvalidStore
	}
	before, err := root.Stat(".")
	if err != nil || !privateArtifactObserverRoot(before) {
		return DeletionReceipt{}, false, ErrInvalidStoreRoot
	}
	name := artifactDeletionFileName(scope, identity)
	first, firstInfo, present, err := readObservedArtifactFileBounded(ctx, root, name, maxEncodedDeletionRecordBytes, closeFile)
	if err != nil {
		return DeletionReceipt{}, false, err
	}
	var receipt DeletionReceipt
	var completed bool
	if present {
		receipt, completed, err = parseDeletionRecord(first)
		if err != nil {
			return DeletionReceipt{}, false, ErrCorruptArtifact
		}
		if receipt.Scope().Identity() != scope.Identity() || receipt.ArtifactIdentity() != identity {
			return DeletionReceipt{}, false, ErrCorruptArtifact
		}
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return DeletionReceipt{}, false, err
		}
	}
	second, secondInfo, stillPresent, err := readObservedArtifactFileBounded(ctx, root, name, maxEncodedDeletionRecordBytes, closeFile)
	if err != nil {
		return DeletionReceipt{}, false, err
	}
	if present != stillPresent {
		return DeletionReceipt{}, false, ErrCorruptArtifact
	}
	if present && (!sameObservedArtifactFile(firstInfo, secondInfo) || !bytes.Equal(first, second)) {
		return DeletionReceipt{}, false, ErrCorruptArtifact
	}
	after, err := root.Stat(".")
	if err != nil || !privateArtifactObserverRoot(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return DeletionReceipt{}, false, ErrInvalidStoreRoot
	}
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, false, err
	}
	// An expected absence is reported only after the root and context checks pass,
	// so a caller that accepts absence never skips them.
	if !present {
		return DeletionReceipt{}, false, ErrArtifactNotFound
	}
	return receipt, completed, nil
}
